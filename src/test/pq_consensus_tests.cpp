// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <consensus/amount.h>
#include <chainparams.h>
#include <hash.h>
#include <pqkey.h>
#include <script/ctv.h>
#include <script/interpreter.h>
#include <script/pqm.h>
#include <script/script.h>
#include <script/script_error.h>
#include <shielded/v2_bundle.h>
#include <streams.h>
#include <test/util/shielded_account_registry_test_util.h>
#include <test/util/setup_common.h>
#include <test/util/shielded_smile_test_util.h>
#include <test/util/transaction_utils.h>
#include <util/chaintype.h>
#include <validation.h>

#include <boost/test/unit_test.hpp>

#include <array>
#include <cassert>
#include <cstdint>
#include <optional>
#include <vector>

namespace {

constexpr unsigned int P2MR_SCRIPT_FLAGS =
    SCRIPT_VERIFY_P2SH | SCRIPT_VERIFY_WITNESS | SCRIPT_VERIFY_NULLFAIL |
    SCRIPT_VERIFY_CHECKTEMPLATEVERIFY | SCRIPT_VERIFY_CHECKSIGFROMSTACK;

smile2::CompactPublicAccount MakeSmileAccount(uint32_t seed)
{
    return test::shielded::MakeDeterministicCompactPublicAccount(seed);
}

class StubPQChecker final : public BaseSignatureChecker
{
public:
    bool CheckPQSignature(Span<const unsigned char>, Span<const unsigned char>, PQAlgorithm, uint8_t, SigVersion, ScriptExecutionData&) const override
    {
        return true;
    }
};

class StubCTVChecker final : public BaseSignatureChecker
{
public:
    bool CheckCTVHash(Span<const unsigned char>) const override
    {
        return true;
    }
};

class AlwaysTruePQChecker final : public BaseSignatureChecker
{
public:
    bool CheckPQSignature(Span<const unsigned char>, Span<const unsigned char>, PQAlgorithm, uint8_t, SigVersion, ScriptExecutionData&) const override
    {
        return true;
    }
};

struct P2MRSpendContext {
    CMutableTransaction tx_credit;
    CMutableTransaction tx_spend;
    PrecomputedTransactionData txdata;

    explicit P2MRSpendContext(const CScript& script_pub_key)
        : tx_credit(BuildCreditingTransaction(script_pub_key, /*nValue=*/5000)),
          tx_spend(BuildSpendingTransaction(CScript{}, CScriptWitness{}, CTransaction{tx_credit}))
    {
        txdata.Init(tx_spend, {tx_credit.vout.at(0)}, /*force=*/true);
    }
};

std::vector<unsigned char> ToBytes(const uint256& hash)
{
    return std::vector<unsigned char>(hash.begin(), hash.end());
}

CShieldedBundle BuildCTVV2ShieldedBundle()
{
    using namespace shielded::v2;

    const auto spend_account = MakeSmileAccount(0x30);
    const uint256 spend_note_commitment = uint256{0x33};
    const auto registry_witness =
        test::shielded::MakeSingleLeafRegistryWitness(spend_note_commitment, spend_account);
    BOOST_REQUIRE(registry_witness.has_value());

    EncryptedNotePayload encrypted_note;
    encrypted_note.scan_domain = ScanDomain::USER;
    encrypted_note.scan_hint.fill(0x29);
    encrypted_note.ciphertext = {0x90, 0x91, 0x92};
    encrypted_note.ephemeral_key = ComputeLegacyPayloadEphemeralKey(
        Span<const uint8_t>{encrypted_note.ciphertext.data(), encrypted_note.ciphertext.size()});

    SpendDescription spend;
    spend.nullifier = uint256{0x31};
    spend.merkle_anchor = uint256{0x32};
    spend.account_leaf_commitment = registry_witness->second.account_leaf_commitment;
    spend.account_registry_proof = registry_witness->second;
    spend.note_commitment = spend_note_commitment;
    spend.value_commitment = uint256{0x34};

    OutputDescription output;
    output.note_class = NoteClass::USER;
    output.smile_account = MakeSmileAccount(0x35);
    output.note_commitment = smile2::ComputeCompactPublicAccountHash(*output.smile_account);
    output.value_commitment = smile2::ComputeSmileOutputCoinHash(output.smile_account->public_coin);
    output.encrypted_note = encrypted_note;

    SendPayload payload;
    payload.spend_anchor = uint256{0x37};
    payload.account_registry_anchor = registry_witness->first;
    payload.spends = {spend};
    payload.outputs = {output};
    payload.fee = 9;
    payload.value_balance = payload.fee;

    ProofEnvelope envelope;
    envelope.proof_kind = ProofKind::DIRECT_SMILE;
    envelope.membership_proof_kind = ProofComponentKind::SMILE_MEMBERSHIP;
    envelope.amount_proof_kind = ProofComponentKind::SMILE_BALANCE;
    envelope.balance_proof_kind = ProofComponentKind::SMILE_BALANCE;
    envelope.settlement_binding_kind = SettlementBindingKind::NONE;
    envelope.statement_digest = uint256{0x38};

    TransactionBundle tx_bundle;
    tx_bundle.header.family_id = TransactionFamily::V2_SEND;
    tx_bundle.header.proof_envelope = envelope;
    tx_bundle.header.payload_digest = ComputeSendPayloadDigest(payload);
    tx_bundle.payload = payload;
    tx_bundle.proof_payload = {0xAA, 0xBB, 0xCC};

    CShieldedBundle bundle;
    bundle.v2_bundle = tx_bundle;
    return bundle;
}

CScript BuildP2MROutput(const uint256& merkle_root);

std::vector<unsigned char> BuildP2MRLeafWithSize(size_t size)
{
    std::vector<unsigned char> script(size, static_cast<unsigned char>(OP_NOP));
    if (!script.empty()) {
        script.front() = static_cast<unsigned char>(OP_1);
    }
    return script;
}

std::vector<unsigned char> BuildOversizedPushLeafScript(size_t push_size)
{
    std::vector<unsigned char> script;
    script.reserve(5 + push_size);
    script.push_back(static_cast<unsigned char>(OP_PUSHDATA4));
    script.push_back(static_cast<unsigned char>(push_size & 0xFF));
    script.push_back(static_cast<unsigned char>((push_size >> 8) & 0xFF));
    script.push_back(static_cast<unsigned char>((push_size >> 16) & 0xFF));
    script.push_back(static_cast<unsigned char>((push_size >> 24) & 0xFF));
    script.insert(script.end(), push_size, 0x42);
    return script;
}

std::vector<unsigned char> BuildCTVOnlyLeafScript(const uint256& ctv_hash)
{
    CScript script;
    script << ToBytes(ctv_hash) << OP_CHECKTEMPLATEVERIFY;
    return std::vector<unsigned char>(script.begin(), script.end());
}

std::vector<unsigned char> BuildCTVChecksigLeafScript(const uint256& ctv_hash, PQAlgorithm algo, Span<const unsigned char> pubkey)
{
    CScript prefix;
    prefix << ToBytes(ctv_hash) << OP_CHECKTEMPLATEVERIFY << OP_DROP;
    std::vector<unsigned char> script(prefix.begin(), prefix.end());
    const std::vector<unsigned char> checksig_leaf = BuildP2MRScript(algo, pubkey);
    script.insert(script.end(), checksig_leaf.begin(), checksig_leaf.end());
    return script;
}

uint256 ComputeCTVHashForTemplateSpend()
{
    const CMutableTransaction tx_credit = BuildCreditingTransaction(BuildP2MROutput(uint256::ONE), /*nValue=*/5000);
    const CMutableTransaction tx_spend = BuildSpendingTransaction(CScript{}, CScriptWitness{}, CTransaction{tx_credit});
    PrecomputedTransactionData txdata;
    txdata.Init(tx_spend, {tx_credit.vout.at(0)}, /*force=*/true);
    return ComputeCTVHash(CTransaction{tx_spend}, /*nIn=*/0, txdata);
}

uint256 ComputeCTVHashForInputIndexOneTemplate()
{
    CMutableTransaction tx;
    tx.version = 1;
    tx.nLockTime = 0;
    tx.vin.resize(2);
    tx.vout.resize(1);
    tx.vin[0].nSequence = CTxIn::SEQUENCE_FINAL;
    tx.vin[1].nSequence = CTxIn::SEQUENCE_FINAL;
    tx.vout[0].nValue = 5000;
    tx.vout[0].scriptPubKey = CScript{};

    PrecomputedTransactionData txdata;
    txdata.Init(tx, {}, /*force=*/true);
    return ComputeCTVHash(tx, /*nIn=*/1, txdata);
}

template <typename T>
std::vector<unsigned char> BuildCTVPreimage(const T& tx, uint32_t nIn, const PrecomputedTransactionData& txdata)
{
    DataStream preimage{};
    preimage << tx.version;
    preimage << tx.nLockTime;
    if (txdata.m_ctv_has_scriptsigs) {
        preimage << txdata.m_ctv_scriptsigs_hash;
    }
    preimage << static_cast<uint32_t>(tx.vin.size());
    preimage << txdata.m_sequences_single_hash;
    preimage << static_cast<uint32_t>(tx.vout.size());
    preimage << txdata.m_outputs_single_hash;
    if (txdata.m_ctv_has_shielded_bundle) {
        preimage << txdata.m_ctv_shielded_bundle_hash;
    }
    preimage << nIn;
    return std::vector<unsigned char>(UCharCast(preimage.data()), UCharCast(preimage.data()) + preimage.size());
}

CScript BuildP2MROutput(const uint256& merkle_root)
{
    CScript script;
    script << OP_2 << ToBytes(merkle_root);
    return script;
}

CBlock BuildSingleCoinbaseBlock(const std::vector<CTxOut>& outputs)
{
    CMutableTransaction coinbase;
    coinbase.vin.resize(1);
    coinbase.vin[0].prevout.SetNull();
    coinbase.vin[0].scriptSig = CScript{} << 1 << OP_0;
    coinbase.vout = outputs;

    CBlock block;
    block.vtx.emplace_back(MakeTransactionRef(std::move(coinbase)));
    return block;
}

std::optional<uint256> ComputeP2MRSighash(
    P2MRSpendContext& ctx,
    Span<const unsigned char> leaf_script,
    uint8_t leaf_version = P2MR_LEAF_VERSION,
    uint8_t hash_type = SIGHASH_DEFAULT,
    const std::vector<unsigned char>* annex = nullptr)
{
    ScriptExecutionData execdata;
    if (annex != nullptr) {
        execdata.m_annex_hash = (HashWriter{} << *annex).GetSHA256();
        execdata.m_annex_present = true;
    } else {
        execdata.m_annex_present = false;
    }
    execdata.m_annex_init = true;
    execdata.m_tapleaf_hash = ComputeP2MRLeafHash(leaf_version, leaf_script);
    execdata.m_tapleaf_hash_init = true;
    execdata.m_codeseparator_pos = 0xFFFFFFFFU;
    execdata.m_codeseparator_pos_init = true;

    uint256 sighash;
    if (!SignatureHashSchnorr(
            sighash,
            execdata,
            ctx.tx_spend,
            /*in_pos=*/0,
            hash_type,
            SigVersion::P2MR,
            ctx.txdata,
            MissingDataBehavior::ASSERT_FAIL)) {
        return std::nullopt;
    }
    return sighash;
}

std::optional<CScriptWitness> BuildSignedMultisigLeafP2MRWitness(
    P2MRSpendContext& ctx,
    const std::vector<CPQKey>& keys_in_script_order,
    size_t threshold,
    Span<const unsigned char> leaf_script)
{
    if (keys_in_script_order.empty()) return std::nullopt;
    if (threshold < 1 || threshold > keys_in_script_order.size()) return std::nullopt;

    const auto sighash = ComputeP2MRSighash(ctx, leaf_script);
    if (!sighash.has_value()) return std::nullopt;

    std::vector<std::vector<unsigned char>> sigs(keys_in_script_order.size());
    for (size_t i = 0; i < threshold; ++i) {
        if (!keys_in_script_order[i].Sign(*sighash, sigs[i])) return std::nullopt;
    }

    CScriptWitness witness;
    witness.stack.reserve(sigs.size() + 2);
    for (size_t i = sigs.size(); i > 0; --i) {
        witness.stack.push_back(std::move(sigs[i - 1]));
    }
    witness.stack.push_back(std::vector<unsigned char>(leaf_script.begin(), leaf_script.end()));
    witness.stack.push_back({P2MR_LEAF_VERSION});
    return witness;
}

bool VerifyP2MRSpend(P2MRSpendContext& ctx, const CScriptWitness& witness, ScriptError& error)
{
    ctx.tx_spend.vin.at(0).scriptWitness = witness;
    return VerifyScript(
        ctx.tx_spend.vin.at(0).scriptSig,
        ctx.tx_credit.vout.at(0).scriptPubKey,
        &ctx.tx_spend.vin.at(0).scriptWitness,
        P2MR_SCRIPT_FLAGS,
        MutableTransactionSignatureChecker(
            &ctx.tx_spend,
            /*nIn=*/0,
            ctx.tx_credit.vout.at(0).nValue,
            ctx.txdata,
            MissingDataBehavior::ASSERT_FAIL),
        &error);
}

bool VerifyP2MRSpendWithFlags(P2MRSpendContext& ctx, const CScriptWitness& witness, unsigned int flags, ScriptError& error)
{
    ctx.tx_spend.vin.at(0).scriptWitness = witness;
    return VerifyScript(
        ctx.tx_spend.vin.at(0).scriptSig,
        ctx.tx_credit.vout.at(0).scriptPubKey,
        &ctx.tx_spend.vin.at(0).scriptWitness,
        flags,
        MutableTransactionSignatureChecker(
            &ctx.tx_spend,
            /*nIn=*/0,
            ctx.tx_credit.vout.at(0).nValue,
            ctx.txdata,
            MissingDataBehavior::ASSERT_FAIL),
        &error);
}

uint256 ComputeCSFSHash(Span<const unsigned char> msg)
{
    HashWriter hasher = HASHER_CSFS;
    hasher.write(MakeByteSpan(msg));
    return hasher.GetSHA256();
}

std::vector<unsigned char> CreateCSFSSignature(const CPQKey& key, Span<const unsigned char> msg)
{
    std::vector<unsigned char> sig;
    const bool ok = key.Sign(ComputeCSFSHash(msg), sig);
    assert(ok);
    return sig;
}

bool EvalP2MRScript(std::vector<std::vector<unsigned char>>& stack,
                    const CScript& script,
                    unsigned int flags,
                    const BaseSignatureChecker& checker,
                    ScriptExecutionData& execdata,
                    ScriptError& err)
{
    return EvalScript(stack, script, flags, checker, SigVersion::P2MR, execdata, &err);
}

} // namespace

BOOST_FIXTURE_TEST_SUITE(pq_consensus_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(witness_v2_recognized_as_p2mr)
{
    const uint256 merkle_root = uint256::ONE;
    const CScript script_pub_key = BuildP2MROutput(merkle_root);

    int version = -1;
    std::vector<unsigned char> program;
    BOOST_REQUIRE(script_pub_key.IsWitnessProgram(version, program));
    BOOST_CHECK_EQUAL(version, 2);
    BOOST_CHECK_EQUAL(program.size(), WITNESS_V2_P2MR_SIZE);
}

BOOST_AUTO_TEST_CASE(p2mr_single_leaf_mldsa_valid_spend)
{
    CPQKey key;
    key.MakeNewKey(PQAlgorithm::ML_DSA_44);
    BOOST_REQUIRE(key.IsValid());

    const std::vector<unsigned char> leaf_script = BuildP2MRScript(PQAlgorithm::ML_DSA_44, key.GetPubKey());
    const uint256 leaf_hash = ComputeP2MRLeafHash(P2MR_LEAF_VERSION, leaf_script);
    const uint256 merkle_root = ComputeP2MRMerkleRoot({leaf_hash});

    P2MRSpendContext ctx{BuildP2MROutput(merkle_root)};
    const auto sighash = ComputeP2MRSighash(ctx, leaf_script);
    BOOST_REQUIRE(sighash.has_value());

    std::vector<unsigned char> signature;
    BOOST_REQUIRE(key.Sign(*sighash, signature));

    CScriptWitness witness;
    witness.stack = {signature, leaf_script, {P2MR_LEAF_VERSION}};

    ScriptError err{SCRIPT_ERR_UNKNOWN_ERROR};
    BOOST_CHECK(VerifyP2MRSpend(ctx, witness, err));
    BOOST_CHECK_EQUAL(err, SCRIPT_ERR_OK);
}

BOOST_AUTO_TEST_CASE(p2mr_single_leaf_mldsa_invalid_sig_fails)
{
    CPQKey key;
    key.MakeNewKey(PQAlgorithm::ML_DSA_44);
    BOOST_REQUIRE(key.IsValid());

    const std::vector<unsigned char> leaf_script = BuildP2MRScript(PQAlgorithm::ML_DSA_44, key.GetPubKey());
    const uint256 leaf_hash = ComputeP2MRLeafHash(P2MR_LEAF_VERSION, leaf_script);
    const uint256 merkle_root = ComputeP2MRMerkleRoot({leaf_hash});

    P2MRSpendContext ctx{BuildP2MROutput(merkle_root)};
    const auto sighash = ComputeP2MRSighash(ctx, leaf_script);
    BOOST_REQUIRE(sighash.has_value());

    std::vector<unsigned char> signature;
    BOOST_REQUIRE(key.Sign(*sighash, signature));
    signature.front() ^= 0x01;

    CScriptWitness witness;
    witness.stack = {signature, leaf_script, {P2MR_LEAF_VERSION}};

    ScriptError err{SCRIPT_ERR_UNKNOWN_ERROR};
    BOOST_CHECK(!VerifyP2MRSpend(ctx, witness, err));
    BOOST_CHECK_EQUAL(err, SCRIPT_ERR_SIG_MLDSA);
}

BOOST_AUTO_TEST_CASE(p2mr_two_leaf_spend_leaf0_mldsa)
{
    CPQKey ml_key;
    ml_key.MakeNewKey(PQAlgorithm::ML_DSA_44);
    BOOST_REQUIRE(ml_key.IsValid());
    CPQKey slh_key;
    slh_key.MakeNewKey(PQAlgorithm::SLH_DSA_128S);
    BOOST_REQUIRE(slh_key.IsValid());

    const std::vector<unsigned char> leaf0_script = BuildP2MRScript(PQAlgorithm::ML_DSA_44, ml_key.GetPubKey());
    const std::vector<unsigned char> leaf1_script = BuildP2MRScript(PQAlgorithm::SLH_DSA_128S, slh_key.GetPubKey());

    const uint256 leaf0 = ComputeP2MRLeafHash(P2MR_LEAF_VERSION, leaf0_script);
    const uint256 leaf1 = ComputeP2MRLeafHash(P2MR_LEAF_VERSION, leaf1_script);
    const uint256 merkle_root = ComputeP2MRMerkleRoot({leaf0, leaf1});

    P2MRSpendContext ctx{BuildP2MROutput(merkle_root)};
    const auto sighash = ComputeP2MRSighash(ctx, leaf0_script);
    BOOST_REQUIRE(sighash.has_value());

    std::vector<unsigned char> signature;
    BOOST_REQUIRE(ml_key.Sign(*sighash, signature));

    std::vector<unsigned char> control{P2MR_LEAF_VERSION};
    control.insert(control.end(), leaf1.begin(), leaf1.end());

    CScriptWitness witness;
    witness.stack = {signature, leaf0_script, control};

    ScriptError err{SCRIPT_ERR_UNKNOWN_ERROR};
    BOOST_CHECK(VerifyP2MRSpend(ctx, witness, err));
    BOOST_CHECK_EQUAL(err, SCRIPT_ERR_OK);
}

BOOST_AUTO_TEST_CASE(p2mr_two_leaf_spend_leaf1_slhdsa)
{
    CPQKey ml_key;
    ml_key.MakeNewKey(PQAlgorithm::ML_DSA_44);
    BOOST_REQUIRE(ml_key.IsValid());
    CPQKey slh_key;
    slh_key.MakeNewKey(PQAlgorithm::SLH_DSA_128S);
    BOOST_REQUIRE(slh_key.IsValid());

    const std::vector<unsigned char> leaf0_script = BuildP2MRScript(PQAlgorithm::ML_DSA_44, ml_key.GetPubKey());
    const std::vector<unsigned char> leaf1_script = BuildP2MRScript(PQAlgorithm::SLH_DSA_128S, slh_key.GetPubKey());

    const uint256 leaf0 = ComputeP2MRLeafHash(P2MR_LEAF_VERSION, leaf0_script);
    const uint256 leaf1 = ComputeP2MRLeafHash(P2MR_LEAF_VERSION, leaf1_script);
    const uint256 merkle_root = ComputeP2MRMerkleRoot({leaf0, leaf1});

    P2MRSpendContext ctx{BuildP2MROutput(merkle_root)};
    const auto sighash = ComputeP2MRSighash(ctx, leaf1_script);
    BOOST_REQUIRE(sighash.has_value());

    std::vector<unsigned char> signature;
    BOOST_REQUIRE(slh_key.Sign(*sighash, signature));

    std::vector<unsigned char> control{P2MR_LEAF_VERSION};
    control.insert(control.end(), leaf0.begin(), leaf0.end());

    CScriptWitness witness;
    witness.stack = {signature, leaf1_script, control};

    ScriptError err{SCRIPT_ERR_UNKNOWN_ERROR};
    BOOST_CHECK(VerifyP2MRSpend(ctx, witness, err));
    BOOST_CHECK_EQUAL(err, SCRIPT_ERR_OK);
}

BOOST_AUTO_TEST_CASE(p2mr_wrong_merkle_proof_fails)
{
    CPQKey ml_key;
    ml_key.MakeNewKey(PQAlgorithm::ML_DSA_44);
    BOOST_REQUIRE(ml_key.IsValid());
    CPQKey slh_key;
    slh_key.MakeNewKey(PQAlgorithm::SLH_DSA_128S);
    BOOST_REQUIRE(slh_key.IsValid());

    const std::vector<unsigned char> leaf0_script = BuildP2MRScript(PQAlgorithm::ML_DSA_44, ml_key.GetPubKey());
    const std::vector<unsigned char> leaf1_script = BuildP2MRScript(PQAlgorithm::SLH_DSA_128S, slh_key.GetPubKey());

    const uint256 leaf0 = ComputeP2MRLeafHash(P2MR_LEAF_VERSION, leaf0_script);
    const uint256 leaf1 = ComputeP2MRLeafHash(P2MR_LEAF_VERSION, leaf1_script);
    const uint256 merkle_root = ComputeP2MRMerkleRoot({leaf0, leaf1});

    P2MRSpendContext ctx{BuildP2MROutput(merkle_root)};
    const auto sighash = ComputeP2MRSighash(ctx, leaf0_script);
    BOOST_REQUIRE(sighash.has_value());

    std::vector<unsigned char> signature;
    BOOST_REQUIRE(ml_key.Sign(*sighash, signature));

    std::vector<unsigned char> control{P2MR_LEAF_VERSION};
    control.insert(control.end(), leaf1.begin(), leaf1.end());
    control.back() ^= 0x01;

    CScriptWitness witness;
    witness.stack = {signature, leaf0_script, control};

    ScriptError err{SCRIPT_ERR_UNKNOWN_ERROR};
    BOOST_CHECK(!VerifyP2MRSpend(ctx, witness, err));
    BOOST_CHECK_EQUAL(err, SCRIPT_ERR_WITNESS_PROGRAM_MISMATCH);
}

BOOST_AUTO_TEST_CASE(p2mr_wrong_leaf_version_fails)
{
    CPQKey key;
    key.MakeNewKey(PQAlgorithm::ML_DSA_44);
    BOOST_REQUIRE(key.IsValid());

    const std::vector<unsigned char> leaf_script = BuildP2MRScript(PQAlgorithm::ML_DSA_44, key.GetPubKey());
    const uint256 leaf_hash = ComputeP2MRLeafHash(P2MR_LEAF_VERSION, leaf_script);
    const uint256 merkle_root = ComputeP2MRMerkleRoot({leaf_hash});

    P2MRSpendContext ctx{BuildP2MROutput(merkle_root)};
    const auto sighash = ComputeP2MRSighash(ctx, leaf_script);
    BOOST_REQUIRE(sighash.has_value());

    std::vector<unsigned char> signature;
    BOOST_REQUIRE(key.Sign(*sighash, signature));

    CScriptWitness witness;
    witness.stack = {signature, leaf_script, {0xc0}};

    ScriptError err{SCRIPT_ERR_UNKNOWN_ERROR};
    BOOST_CHECK(!VerifyP2MRSpend(ctx, witness, err));
    BOOST_CHECK_EQUAL(err, SCRIPT_ERR_P2MR_WRONG_LEAF_VERSION);
}

BOOST_AUTO_TEST_CASE(p2mr_empty_witness_fails)
{
    const uint256 merkle_root = uint256::ONE;
    P2MRSpendContext ctx{BuildP2MROutput(merkle_root)};

    CScriptWitness witness;
    ScriptError err{SCRIPT_ERR_UNKNOWN_ERROR};
    BOOST_CHECK(!VerifyP2MRSpend(ctx, witness, err));
    BOOST_CHECK_EQUAL(err, SCRIPT_ERR_WITNESS_PROGRAM_WITNESS_EMPTY);
}

BOOST_AUTO_TEST_CASE(p2mr_wrong_control_size_fails)
{
    CPQKey key;
    key.MakeNewKey(PQAlgorithm::ML_DSA_44);
    BOOST_REQUIRE(key.IsValid());

    const std::vector<unsigned char> leaf_script = BuildP2MRScript(PQAlgorithm::ML_DSA_44, key.GetPubKey());
    const uint256 leaf_hash = ComputeP2MRLeafHash(P2MR_LEAF_VERSION, leaf_script);
    const uint256 merkle_root = ComputeP2MRMerkleRoot({leaf_hash});

    P2MRSpendContext ctx{BuildP2MROutput(merkle_root)};
    const auto sighash = ComputeP2MRSighash(ctx, leaf_script);
    BOOST_REQUIRE(sighash.has_value());

    std::vector<unsigned char> signature;
    BOOST_REQUIRE(key.Sign(*sighash, signature));

    CScriptWitness witness;
    witness.stack = {signature, leaf_script, {P2MR_LEAF_VERSION, 0x00}};

    ScriptError err{SCRIPT_ERR_UNKNOWN_ERROR};
    BOOST_CHECK(!VerifyP2MRSpend(ctx, witness, err));
    BOOST_CHECK_EQUAL(err, SCRIPT_ERR_P2MR_WRONG_CONTROL_SIZE);
}

BOOST_AUTO_TEST_CASE(p2mr_reserved_falcon_opsuccess_slots_succeed)
{
    const std::array<opcodetype, 3> reserved_slots{
        OP_CHECKSIG_FALCON,
        OP_CHECKSIGADD_FALCON,
        OP_CHECKSIGFROMSTACK_FALCON,
    };

    for (const opcodetype opcode : reserved_slots) {
        const std::vector<unsigned char> leaf_script{static_cast<unsigned char>(opcode)};
        const uint256 leaf_hash = ComputeP2MRLeafHash(P2MR_LEAF_VERSION, leaf_script);
        const uint256 merkle_root = ComputeP2MRMerkleRoot({leaf_hash});

        P2MRSpendContext ctx{BuildP2MROutput(merkle_root)};
        CScriptWitness witness;
        witness.stack = {leaf_script, {P2MR_LEAF_VERSION}};

        ScriptError err{SCRIPT_ERR_UNKNOWN_ERROR};
        BOOST_CHECK_MESSAGE(VerifyP2MRSpend(ctx, witness, err), GetOpName(opcode));
        BOOST_CHECK_EQUAL(err, SCRIPT_ERR_OK);
    }
}

BOOST_AUTO_TEST_CASE(p2mr_reserved_falcon_opsuccess_slot_discouraged_by_flag)
{
    const std::vector<unsigned char> leaf_script{static_cast<unsigned char>(OP_CHECKSIG_FALCON)};
    const uint256 leaf_hash = ComputeP2MRLeafHash(P2MR_LEAF_VERSION, leaf_script);
    const uint256 merkle_root = ComputeP2MRMerkleRoot({leaf_hash});

    P2MRSpendContext ctx{BuildP2MROutput(merkle_root)};
    CScriptWitness witness;
    witness.stack = {leaf_script, {P2MR_LEAF_VERSION}};

    ScriptError err{SCRIPT_ERR_UNKNOWN_ERROR};
    BOOST_CHECK(!VerifyP2MRSpendWithFlags(ctx, witness, P2MR_SCRIPT_FLAGS | SCRIPT_VERIFY_DISCOURAGE_OP_SUCCESS, err));
    BOOST_CHECK_EQUAL(err, SCRIPT_ERR_DISCOURAGE_OP_SUCCESS);
}

BOOST_AUTO_TEST_CASE(p2mr_annex_signature_hash_commits_to_annex)
{
    CPQKey key;
    key.MakeNewKey(PQAlgorithm::ML_DSA_44);
    BOOST_REQUIRE(key.IsValid());

    const std::vector<unsigned char> leaf_script = BuildP2MRScript(PQAlgorithm::ML_DSA_44, key.GetPubKey());
    const uint256 leaf_hash = ComputeP2MRLeafHash(P2MR_LEAF_VERSION, leaf_script);
    const uint256 merkle_root = ComputeP2MRMerkleRoot({leaf_hash});
    const std::vector<unsigned char> annex{ANNEX_TAG, 0x01, 0x02, 0x03};

    P2MRSpendContext ctx{BuildP2MROutput(merkle_root)};
    const auto sighash_with_annex = ComputeP2MRSighash(ctx, leaf_script, P2MR_LEAF_VERSION, SIGHASH_DEFAULT, &annex);
    BOOST_REQUIRE(sighash_with_annex.has_value());
    const auto sighash_without_annex = ComputeP2MRSighash(ctx, leaf_script);
    BOOST_REQUIRE(sighash_without_annex.has_value());
    BOOST_CHECK(*sighash_with_annex != *sighash_without_annex);

    std::vector<unsigned char> sig_with_annex;
    BOOST_REQUIRE(key.Sign(*sighash_with_annex, sig_with_annex));
    std::vector<unsigned char> sig_without_annex;
    BOOST_REQUIRE(key.Sign(*sighash_without_annex, sig_without_annex));

    {
        CScriptWitness witness;
        witness.stack = {sig_with_annex, leaf_script, {P2MR_LEAF_VERSION}, annex};
        ScriptError err{SCRIPT_ERR_UNKNOWN_ERROR};
        BOOST_CHECK(VerifyP2MRSpend(ctx, witness, err));
        BOOST_CHECK_EQUAL(err, SCRIPT_ERR_OK);
    }

    {
        CScriptWitness witness;
        witness.stack = {sig_without_annex, leaf_script, {P2MR_LEAF_VERSION}, annex};
        ScriptError err{SCRIPT_ERR_UNKNOWN_ERROR};
        BOOST_CHECK(!VerifyP2MRSpend(ctx, witness, err));
        BOOST_CHECK_EQUAL(err, SCRIPT_ERR_SIG_MLDSA);
    }
}

BOOST_AUTO_TEST_CASE(op_checksig_mldsa_pops_correct_stack)
{
    const std::vector<unsigned char> signature(MLDSA44_SIGNATURE_SIZE, 0x01);
    const std::vector<unsigned char> pubkey(MLDSA44_PUBKEY_SIZE, 0x02);
    const std::vector<unsigned char> script_bytes = BuildP2MRScript(PQAlgorithm::ML_DSA_44, pubkey);
    const CScript script(script_bytes.begin(), script_bytes.end());

    std::vector<std::vector<unsigned char>> stack{signature};
    ScriptExecutionData execdata;
    execdata.m_validation_weight_left_init = true;
    execdata.m_validation_weight_left = VALIDATION_WEIGHT_PER_MLDSA_SIGOP;
    ScriptError err{SCRIPT_ERR_UNKNOWN_ERROR};
    const StubPQChecker checker;

    BOOST_REQUIRE(EvalScript(stack, script, SCRIPT_VERIFY_NONE, checker, SigVersion::P2MR, execdata, &err));
    BOOST_CHECK_EQUAL(stack.size(), 1U);
    BOOST_CHECK_EQUAL(stack.back().size(), 1U);
    BOOST_CHECK_EQUAL(stack.back().front(), 1U);
}

BOOST_AUTO_TEST_CASE(op_checksig_mldsa_disallowed_flag_fails)
{
    const std::vector<unsigned char> signature(MLDSA44_SIGNATURE_SIZE, 0x01);
    const std::vector<unsigned char> pubkey(MLDSA44_PUBKEY_SIZE, 0x02);
    const std::vector<unsigned char> script_bytes = BuildP2MRScript(PQAlgorithm::ML_DSA_44, pubkey);
    const CScript script(script_bytes.begin(), script_bytes.end());

    std::vector<std::vector<unsigned char>> stack{signature};
    ScriptExecutionData execdata;
    execdata.m_validation_weight_left_init = true;
    execdata.m_validation_weight_left = VALIDATION_WEIGHT_PER_MLDSA_SIGOP;
    ScriptError err{SCRIPT_ERR_UNKNOWN_ERROR};
    const StubPQChecker checker;

    BOOST_CHECK(!EvalScript(stack, script, SCRIPT_VERIFY_DISALLOW_MLDSA, checker, SigVersion::P2MR, execdata, &err));
    BOOST_CHECK_EQUAL(err, SCRIPT_ERR_DISABLED_OPCODE);
}

BOOST_AUTO_TEST_CASE(op_checksig_mldsa_wrong_pubkey_size_fails)
{
    const std::vector<unsigned char> signature(MLDSA44_SIGNATURE_SIZE, 0x01);
    const std::vector<unsigned char> script_bytes{
        static_cast<unsigned char>(OP_PUSHDATA2),
        0x01,
        0x00,
        0x02,
        static_cast<unsigned char>(OP_CHECKSIG_MLDSA),
    };
    const CScript script(script_bytes.begin(), script_bytes.end());

    std::vector<std::vector<unsigned char>> stack{signature};
    ScriptExecutionData execdata;
    execdata.m_validation_weight_left_init = true;
    execdata.m_validation_weight_left = VALIDATION_WEIGHT_PER_SLHDSA_SIGOP;
    ScriptError err{SCRIPT_ERR_UNKNOWN_ERROR};
    const StubPQChecker checker;

    BOOST_CHECK(!EvalScript(stack, script, SCRIPT_VERIFY_NONE, checker, SigVersion::P2MR, execdata, &err));
    BOOST_CHECK_EQUAL(err, SCRIPT_ERR_PQ_PUBKEY_SIZE);
}

BOOST_AUTO_TEST_CASE(op_checksig_slhdsa_pops_correct_stack)
{
    const std::vector<unsigned char> signature(SLHDSA128S_SIGNATURE_SIZE, 0x03);
    const std::vector<unsigned char> pubkey(SLHDSA128S_PUBKEY_SIZE, 0x04);
    const std::vector<unsigned char> script_bytes = BuildP2MRScript(PQAlgorithm::SLH_DSA_128S, pubkey);
    const CScript script(script_bytes.begin(), script_bytes.end());

    std::vector<std::vector<unsigned char>> stack{signature};
    ScriptExecutionData execdata;
    execdata.m_validation_weight_left_init = true;
    execdata.m_validation_weight_left = VALIDATION_WEIGHT_PER_SLHDSA_SIGOP;
    ScriptError err{SCRIPT_ERR_UNKNOWN_ERROR};
    const StubPQChecker checker;

    BOOST_REQUIRE(EvalScript(stack, script, SCRIPT_VERIFY_NONE, checker, SigVersion::P2MR, execdata, &err));
    BOOST_CHECK_EQUAL(stack.size(), 1U);
    BOOST_CHECK_EQUAL(stack.back().size(), 1U);
    BOOST_CHECK_EQUAL(stack.back().front(), 1U);
}

BOOST_AUTO_TEST_CASE(op_checksig_slhdsa_with_mldsa_disable_flag_still_succeeds)
{
    const std::vector<unsigned char> signature(SLHDSA128S_SIGNATURE_SIZE, 0x03);
    const std::vector<unsigned char> pubkey(SLHDSA128S_PUBKEY_SIZE, 0x04);
    const std::vector<unsigned char> script_bytes = BuildP2MRScript(PQAlgorithm::SLH_DSA_128S, pubkey);
    const CScript script(script_bytes.begin(), script_bytes.end());

    std::vector<std::vector<unsigned char>> stack{signature};
    ScriptExecutionData execdata;
    execdata.m_validation_weight_left_init = true;
    execdata.m_validation_weight_left = VALIDATION_WEIGHT_PER_SLHDSA_SIGOP;
    ScriptError err{SCRIPT_ERR_UNKNOWN_ERROR};
    const StubPQChecker checker;

    BOOST_REQUIRE(EvalScript(stack, script, SCRIPT_VERIFY_DISALLOW_MLDSA, checker, SigVersion::P2MR, execdata, &err));
    BOOST_CHECK_EQUAL(stack.size(), 1U);
    BOOST_CHECK_EQUAL(stack.back().size(), 1U);
    BOOST_CHECK_EQUAL(stack.back().front(), 1U);
}

BOOST_AUTO_TEST_CASE(op_checksig_pq_rejected_in_tapscript)
{
    const StubPQChecker checker;
    ScriptExecutionData execdata;
    for (const auto opcode : {OP_CHECKSIG_MLDSA, OP_CHECKSIG_SLHDSA}) {
        std::vector<std::vector<unsigned char>> stack;
        ScriptError err{SCRIPT_ERR_UNKNOWN_ERROR};
        const CScript script{opcode};
        BOOST_CHECK(!EvalScript(stack, script, SCRIPT_VERIFY_NONE, checker, SigVersion::TAPSCRIPT, execdata, &err));
        BOOST_CHECK_EQUAL(err, SCRIPT_ERR_BAD_OPCODE);
    }
}

BOOST_AUTO_TEST_CASE(op_checksigadd_mldsa_increments_counter)
{
    const StubPQChecker checker;
    const std::vector<unsigned char> signature(MLDSA44_SIGNATURE_SIZE, 0x61);
    const std::vector<unsigned char> pubkey(MLDSA44_PUBKEY_SIZE, 0x62);

    CScript script;
    script << pubkey << OP_CHECKSIGADD_MLDSA;

    std::vector<std::vector<unsigned char>> stack{signature, CScriptNum{7}.getvch()};
    ScriptExecutionData execdata;
    execdata.m_validation_weight_left_init = true;
    execdata.m_validation_weight_left = VALIDATION_WEIGHT_PER_MLDSA_MULTISIG_SIGOP + 3;
    ScriptError err{SCRIPT_ERR_UNKNOWN_ERROR};

    BOOST_REQUIRE(EvalScript(stack, script, SCRIPT_VERIFY_NONE, checker, SigVersion::P2MR, execdata, &err));
    BOOST_REQUIRE_EQUAL(stack.size(), 1U);
    BOOST_CHECK_EQUAL(CScriptNum(stack.back(), /*fRequireMinimal=*/true).getint(), 8);
    BOOST_CHECK_EQUAL(execdata.m_validation_weight_left, 3);
}

BOOST_AUTO_TEST_CASE(op_checksigadd_mldsa_disallowed_flag_fails)
{
    const StubPQChecker checker;
    const std::vector<unsigned char> signature(MLDSA44_SIGNATURE_SIZE, 0x61);
    const std::vector<unsigned char> pubkey(MLDSA44_PUBKEY_SIZE, 0x62);

    CScript script;
    script << pubkey << OP_CHECKSIGADD_MLDSA;

    std::vector<std::vector<unsigned char>> stack{signature, CScriptNum{7}.getvch()};
    ScriptExecutionData execdata;
    execdata.m_validation_weight_left_init = true;
    execdata.m_validation_weight_left = VALIDATION_WEIGHT_PER_MLDSA_MULTISIG_SIGOP + 3;
    ScriptError err{SCRIPT_ERR_UNKNOWN_ERROR};

    BOOST_CHECK(!EvalScript(stack, script, SCRIPT_VERIFY_DISALLOW_MLDSA, checker, SigVersion::P2MR, execdata, &err));
    BOOST_CHECK_EQUAL(err, SCRIPT_ERR_DISABLED_OPCODE);
}


BOOST_AUTO_TEST_CASE(op_checksigadd_slhdsa_empty_sig_keeps_counter)
{
    const StubPQChecker checker;
    const std::vector<unsigned char> pubkey(SLHDSA128S_PUBKEY_SIZE, 0x63);

    CScript script;
    script << pubkey << OP_CHECKSIGADD_SLHDSA;

    std::vector<std::vector<unsigned char>> stack{{}, CScriptNum{5}.getvch()};
    ScriptExecutionData execdata;
    execdata.m_validation_weight_left_init = true;
    execdata.m_validation_weight_left = VALIDATION_WEIGHT_PER_SLHDSA_MULTISIG_SIGOP + 9;
    ScriptError err{SCRIPT_ERR_UNKNOWN_ERROR};

    BOOST_REQUIRE(EvalScript(stack, script, SCRIPT_VERIFY_NONE, checker, SigVersion::P2MR, execdata, &err));
    BOOST_REQUIRE_EQUAL(stack.size(), 1U);
    BOOST_CHECK_EQUAL(CScriptNum(stack.back(), /*fRequireMinimal=*/true).getint(), 5);
    BOOST_CHECK_EQUAL(execdata.m_validation_weight_left, VALIDATION_WEIGHT_PER_SLHDSA_MULTISIG_SIGOP + 9);
}

BOOST_AUTO_TEST_CASE(op_checksigadd_rejected_outside_p2mr)
{
    const StubPQChecker checker;
    const std::vector<unsigned char> signature{0x64};
    const std::vector<unsigned char> pubkey{0x65};
    const std::vector<unsigned char> counter = CScriptNum{1}.getvch();

    for (const auto opcode : {OP_CHECKSIGADD_MLDSA, OP_CHECKSIGADD_SLHDSA}) {
        CScript script;
        script << pubkey << opcode;
        std::vector<std::vector<unsigned char>> stack{signature, counter};
        ScriptExecutionData execdata;
        execdata.m_validation_weight_left_init = true;
        execdata.m_validation_weight_left = VALIDATION_WEIGHT_PER_MLDSA_MULTISIG_SIGOP;
        ScriptError err{SCRIPT_ERR_UNKNOWN_ERROR};
        BOOST_CHECK(!EvalScript(stack, script, SCRIPT_VERIFY_NONE, checker, SigVersion::TAPSCRIPT, execdata, &err));
        BOOST_CHECK_EQUAL(err, SCRIPT_ERR_BAD_OPCODE);
    }
}

BOOST_AUTO_TEST_CASE(op_checksigadd_weight_exhaustion_fails)
{
    const StubPQChecker checker;
    const std::vector<unsigned char> signature(MLDSA44_SIGNATURE_SIZE, 0x66);
    const std::vector<unsigned char> pubkey(MLDSA44_PUBKEY_SIZE, 0x67);

    CScript script;
    script << pubkey << OP_CHECKSIGADD_MLDSA;

    std::vector<std::vector<unsigned char>> stack{signature, CScriptNum{0}.getvch()};
    ScriptExecutionData execdata;
    execdata.m_validation_weight_left_init = true;
    execdata.m_validation_weight_left = VALIDATION_WEIGHT_PER_MLDSA_MULTISIG_SIGOP - 1;
    ScriptError err{SCRIPT_ERR_UNKNOWN_ERROR};

    BOOST_CHECK(!EvalScript(stack, script, SCRIPT_VERIFY_NONE, checker, SigVersion::P2MR, execdata, &err));
    BOOST_CHECK_EQUAL(err, SCRIPT_ERR_TAPSCRIPT_VALIDATION_WEIGHT);
}

BOOST_AUTO_TEST_CASE(op_checksigadd_wrong_pubkey_size_fails)
{
    const StubPQChecker checker;
    const std::vector<unsigned char> signature(MLDSA44_SIGNATURE_SIZE, 0x68);

    CScript script;
    script << std::vector<unsigned char>{0x01} << OP_CHECKSIGADD_MLDSA;

    std::vector<std::vector<unsigned char>> stack{signature, CScriptNum{0}.getvch()};
    ScriptExecutionData execdata;
    execdata.m_validation_weight_left_init = true;
    execdata.m_validation_weight_left = VALIDATION_WEIGHT_PER_MLDSA_MULTISIG_SIGOP;
    ScriptError err{SCRIPT_ERR_UNKNOWN_ERROR};

    BOOST_CHECK(!EvalScript(stack, script, SCRIPT_VERIFY_NONE, checker, SigVersion::P2MR, execdata, &err));
    BOOST_CHECK_EQUAL(err, SCRIPT_ERR_PQ_PUBKEY_SIZE);
}

BOOST_AUTO_TEST_CASE(op_checksigadd_requires_minimal_counter_encoding)
{
    const StubPQChecker checker;
    const std::vector<unsigned char> signature(MLDSA44_SIGNATURE_SIZE, 0x69);
    const std::vector<unsigned char> pubkey(MLDSA44_PUBKEY_SIZE, 0x6A);

    CScript script;
    script << pubkey << OP_CHECKSIGADD_MLDSA;

    // Non-minimal encoding of value 1.
    std::vector<std::vector<unsigned char>> stack{signature, std::vector<unsigned char>{0x01, 0x00}};
    ScriptExecutionData execdata;
    execdata.m_validation_weight_left_init = true;
    execdata.m_validation_weight_left = VALIDATION_WEIGHT_PER_MLDSA_MULTISIG_SIGOP;
    ScriptError err{SCRIPT_ERR_UNKNOWN_ERROR};

    BOOST_CHECK(!EvalScript(stack, script, SCRIPT_VERIFY_NONE, checker, SigVersion::P2MR, execdata, &err));
}


BOOST_AUTO_TEST_CASE(p2mr_existing_primitives_fit_element_limit)
{
    BOOST_CHECK(MLDSA44_PUBKEY_SIZE <= MAX_P2MR_ELEMENT_SIZE);
    BOOST_CHECK(MLDSA44_SIGNATURE_SIZE + 1 <= MAX_P2MR_ELEMENT_SIZE);
    BOOST_CHECK(SLHDSA128S_PUBKEY_SIZE <= MAX_P2MR_ELEMENT_SIZE);
    BOOST_CHECK(SLHDSA128S_SIGNATURE_SIZE + 1 <= MAX_P2MR_ELEMENT_SIZE);
}

BOOST_AUTO_TEST_CASE(p2mr_checksig_mldsa_decrements_validation_weight)
{
    const StubPQChecker checker;
    const std::vector<unsigned char> signature(MLDSA44_SIGNATURE_SIZE, 0x11);
    const std::vector<unsigned char> pubkey(MLDSA44_PUBKEY_SIZE, 0x22);
    const std::vector<unsigned char> script_bytes = BuildP2MRScript(PQAlgorithm::ML_DSA_44, pubkey);
    const CScript script(script_bytes.begin(), script_bytes.end());

    std::vector<std::vector<unsigned char>> stack{signature};
    ScriptExecutionData execdata;
    execdata.m_validation_weight_left_init = true;
    execdata.m_validation_weight_left = VALIDATION_WEIGHT_PER_MLDSA_SIGOP + 77;
    ScriptError err{SCRIPT_ERR_UNKNOWN_ERROR};

    BOOST_REQUIRE(EvalScript(stack, script, SCRIPT_VERIFY_NONE, checker, SigVersion::P2MR, execdata, &err));
    BOOST_CHECK_EQUAL(execdata.m_validation_weight_left, 77);
}

BOOST_AUTO_TEST_CASE(p2mr_checksig_slhdsa_decrements_validation_weight)
{
    const StubPQChecker checker;
    const std::vector<unsigned char> signature(SLHDSA128S_SIGNATURE_SIZE, 0x33);
    const std::vector<unsigned char> pubkey(SLHDSA128S_PUBKEY_SIZE, 0x44);
    const std::vector<unsigned char> script_bytes = BuildP2MRScript(PQAlgorithm::SLH_DSA_128S, pubkey);
    const CScript script(script_bytes.begin(), script_bytes.end());

    std::vector<std::vector<unsigned char>> stack{signature};
    ScriptExecutionData execdata;
    execdata.m_validation_weight_left_init = true;
    execdata.m_validation_weight_left = VALIDATION_WEIGHT_PER_SLHDSA_SIGOP + 101;
    ScriptError err{SCRIPT_ERR_UNKNOWN_ERROR};

    BOOST_REQUIRE(EvalScript(stack, script, SCRIPT_VERIFY_NONE, checker, SigVersion::P2MR, execdata, &err));
    BOOST_CHECK_EQUAL(execdata.m_validation_weight_left, 101);
}

BOOST_AUTO_TEST_CASE(p2mr_checksig_weight_exhaustion_fails)
{
    const StubPQChecker checker;
    const std::vector<unsigned char> signature(MLDSA44_SIGNATURE_SIZE, 0x51);
    const std::vector<unsigned char> pubkey(MLDSA44_PUBKEY_SIZE, 0x52);
    const std::vector<unsigned char> script_bytes = BuildP2MRScript(PQAlgorithm::ML_DSA_44, pubkey);
    const CScript script(script_bytes.begin(), script_bytes.end());

    std::vector<std::vector<unsigned char>> stack{signature};
    ScriptExecutionData execdata;
    execdata.m_validation_weight_left_init = true;
    execdata.m_validation_weight_left = VALIDATION_WEIGHT_PER_MLDSA_SIGOP - 1;
    ScriptError err{SCRIPT_ERR_UNKNOWN_ERROR};

    BOOST_CHECK(!EvalScript(stack, script, SCRIPT_VERIFY_NONE, checker, SigVersion::P2MR, execdata, &err));
    BOOST_CHECK_EQUAL(err, SCRIPT_ERR_TAPSCRIPT_VALIDATION_WEIGHT);
}

BOOST_AUTO_TEST_CASE(p2mr_oversized_exec_stack_element_is_rejected)
{
    const std::vector<unsigned char> leaf_script{
        static_cast<unsigned char>(OP_DROP),
        static_cast<unsigned char>(OP_1),
    };
    const uint256 merkle_root = ComputeP2MRMerkleRoot({ComputeP2MRLeafHash(P2MR_LEAF_VERSION, leaf_script)});
    P2MRSpendContext ctx{BuildP2MROutput(merkle_root)};

    CScriptWitness witness;
    witness.stack = {
        std::vector<unsigned char>(MAX_P2MR_ELEMENT_SIZE + 1, 0x99),
        leaf_script,
        {P2MR_LEAF_VERSION},
    };

    ScriptError err{SCRIPT_ERR_UNKNOWN_ERROR};
    BOOST_CHECK(!VerifyP2MRSpend(ctx, witness, err));
    BOOST_CHECK_EQUAL(err, SCRIPT_ERR_PUSH_SIZE);
}

BOOST_AUTO_TEST_CASE(p2mr_oversized_push_value_is_rejected)
{
    const StubPQChecker checker;
    const std::vector<unsigned char> script_bytes = BuildOversizedPushLeafScript(MAX_P2MR_ELEMENT_SIZE + 1);
    const CScript script(script_bytes.begin(), script_bytes.end());

    std::vector<std::vector<unsigned char>> stack;
    ScriptExecutionData execdata;
    ScriptError err{SCRIPT_ERR_UNKNOWN_ERROR};

    BOOST_CHECK(!EvalScript(stack, script, SCRIPT_VERIFY_NONE, checker, SigVersion::P2MR, execdata, &err));
    BOOST_CHECK_EQUAL(err, SCRIPT_ERR_PUSH_SIZE);
}

BOOST_AUTO_TEST_CASE(p2mr_script_size_cap_rejects_oversized_leaf)
{
    const std::vector<unsigned char> leaf_script = BuildP2MRLeafWithSize(MAX_P2MR_SCRIPT_SIZE + 1);
    const uint256 merkle_root = ComputeP2MRMerkleRoot({ComputeP2MRLeafHash(P2MR_LEAF_VERSION, leaf_script)});
    P2MRSpendContext ctx{BuildP2MROutput(merkle_root)};

    CScriptWitness witness;
    witness.stack = {leaf_script, {P2MR_LEAF_VERSION}};

    ScriptError err{SCRIPT_ERR_UNKNOWN_ERROR};
    BOOST_CHECK(!VerifyP2MRSpend(ctx, witness, err));
    BOOST_CHECK_EQUAL(err, SCRIPT_ERR_SCRIPT_SIZE);
}

BOOST_AUTO_TEST_CASE(p2mr_script_size_cap_accepts_boundary_leaf)
{
    const std::vector<unsigned char> leaf_script = BuildP2MRLeafWithSize(MAX_P2MR_SCRIPT_SIZE);
    const uint256 merkle_root = ComputeP2MRMerkleRoot({ComputeP2MRLeafHash(P2MR_LEAF_VERSION, leaf_script)});
    P2MRSpendContext ctx{BuildP2MROutput(merkle_root)};

    CScriptWitness witness;
    witness.stack = {leaf_script, {P2MR_LEAF_VERSION}};

    ScriptError err{SCRIPT_ERR_UNKNOWN_ERROR};
    BOOST_CHECK(VerifyP2MRSpend(ctx, witness, err));
    BOOST_CHECK_EQUAL(err, SCRIPT_ERR_OK);
}

BOOST_AUTO_TEST_CASE(ctv_preimage_without_scriptsigs_is_84_bytes)
{
    CMutableTransaction tx;
    tx.version = 2;
    tx.nLockTime = 0;
    tx.vin.resize(1);
    tx.vin[0].nSequence = 7;
    tx.vout.resize(1);
    tx.vout[0].nValue = 10'000;
    tx.vout[0].scriptPubKey = CScript{} << OP_1;

    PrecomputedTransactionData txdata;
    txdata.Init(tx, {}, /*force=*/true);
    BOOST_REQUIRE(!txdata.m_ctv_has_scriptsigs);
    BOOST_CHECK_EQUAL(BuildCTVPreimage(tx, 0, txdata).size(), 84U);
}

BOOST_AUTO_TEST_CASE(ctv_preimage_with_scriptsigs_is_116_bytes)
{
    CMutableTransaction tx;
    tx.version = 2;
    tx.nLockTime = 0;
    tx.vin.resize(1);
    tx.vin[0].scriptSig = CScript{} << OP_1;
    tx.vin[0].nSequence = 7;
    tx.vout.resize(1);
    tx.vout[0].nValue = 10'000;
    tx.vout[0].scriptPubKey = CScript{} << OP_1;

    PrecomputedTransactionData txdata;
    txdata.Init(tx, {}, /*force=*/true);
    BOOST_REQUIRE(txdata.m_ctv_has_scriptsigs);
    BOOST_CHECK_EQUAL(BuildCTVPreimage(tx, 0, txdata).size(), 116U);
}

BOOST_AUTO_TEST_CASE(ctv_preimage_with_shielded_bundle_adds_32_byte_digest)
{
    CMutableTransaction tx;
    tx.version = 2;
    tx.nLockTime = 0;
    tx.vin.resize(1);
    tx.vin[0].nSequence = 7;
    tx.vout.resize(1);
    tx.vout[0].nValue = 10'000;
    tx.vout[0].scriptPubKey = CScript{} << OP_1;

    CShieldedBundle bundle;
    bundle.value_balance = -200;
    CShieldedInput input;
    input.nullifier = uint256::ONE;
    input.ring_positions = std::vector<uint64_t>(16, 0);
    bundle.shielded_inputs.push_back(input);
    CShieldedOutput output;
    output.note_commitment = uint256::ONE;
    bundle.shielded_outputs.push_back(output);
    tx.shielded_bundle = std::move(bundle);

    PrecomputedTransactionData txdata;
    txdata.Init(tx, {}, /*force=*/true);
    BOOST_REQUIRE(!txdata.m_ctv_has_scriptsigs);
    BOOST_REQUIRE(txdata.m_ctv_has_shielded_bundle);
    BOOST_CHECK(!txdata.m_ctv_shielded_bundle_hash.IsNull());
    BOOST_CHECK_EQUAL(BuildCTVPreimage(tx, 0, txdata).size(), 116U);
}

BOOST_AUTO_TEST_CASE(ctv_hash_commits_to_shielded_bundle_fields)
{
    CMutableTransaction tx;
    tx.version = 2;
    tx.nLockTime = 0;
    tx.vin.resize(1);
    tx.vin[0].nSequence = 7;
    tx.vout.resize(1);
    tx.vout[0].nValue = 10'000;
    tx.vout[0].scriptPubKey = CScript{} << OP_1;

    CShieldedBundle bundle;
    bundle.value_balance = -200;
    CShieldedInput input;
    input.nullifier = uint256::ONE;
    input.ring_positions = std::vector<uint64_t>(16, 0);
    bundle.shielded_inputs.push_back(input);
    CShieldedOutput output;
    output.note_commitment = uint256::ONE;
    bundle.shielded_outputs.push_back(output);
    CViewGrant grant;
    grant.kem_ct.fill(0x11);
    grant.nonce.fill(0x22);
    grant.encrypted_data = {0x33, 0x44, 0x55};
    bundle.view_grants.push_back(grant);
    bundle.proof = {0xAA, 0xBB, 0xCC};
    tx.shielded_bundle = std::move(bundle);

    PrecomputedTransactionData txdata;
    txdata.Init(tx, {}, /*force=*/true);
    HashWriter shielded_hw{};
    shielded_hw << tx.shielded_bundle.value_balance;
    shielded_hw << tx.shielded_bundle.shielded_inputs;
    shielded_hw << tx.shielded_bundle.shielded_outputs;
    shielded_hw << tx.shielded_bundle.view_grants;
    shielded_hw << tx.shielded_bundle.proof;
    BOOST_CHECK_EQUAL(txdata.m_ctv_shielded_bundle_hash, shielded_hw.GetSHA256());
    const uint256 baseline = ComputeCTVHash(tx, 0, txdata);

    CMutableTransaction tx_value_balance = tx;
    tx_value_balance.shielded_bundle.value_balance = -201;
    txdata = PrecomputedTransactionData{};
    txdata.Init(tx_value_balance, {}, /*force=*/true);
    BOOST_CHECK(ComputeCTVHash(tx_value_balance, 0, txdata) != baseline);

    CMutableTransaction tx_output_commitment = tx;
    tx_output_commitment.shielded_bundle.shielded_outputs[0].note_commitment = uint256{};
    txdata = PrecomputedTransactionData{};
    txdata.Init(tx_output_commitment, {}, /*force=*/true);
    BOOST_CHECK(ComputeCTVHash(tx_output_commitment, 0, txdata) != baseline);

    CMutableTransaction tx_input_nullifier = tx;
    tx_input_nullifier.shielded_bundle.shielded_inputs[0].nullifier = uint256{};
    txdata = PrecomputedTransactionData{};
    txdata.Init(tx_input_nullifier, {}, /*force=*/true);
    BOOST_CHECK(ComputeCTVHash(tx_input_nullifier, 0, txdata) != baseline);

    CMutableTransaction tx_ring_positions = tx;
    tx_ring_positions.shielded_bundle.shielded_inputs[0].ring_positions[0] ^= 1;
    txdata = PrecomputedTransactionData{};
    txdata.Init(tx_ring_positions, {}, /*force=*/true);
    BOOST_CHECK(ComputeCTVHash(tx_ring_positions, 0, txdata) != baseline);

    CMutableTransaction tx_view_grant = tx;
    tx_view_grant.shielded_bundle.view_grants[0].encrypted_data[0] ^= 1;
    txdata = PrecomputedTransactionData{};
    txdata.Init(tx_view_grant, {}, /*force=*/true);
    BOOST_CHECK(ComputeCTVHash(tx_view_grant, 0, txdata) != baseline);

    CMutableTransaction tx_proof = tx;
    tx_proof.shielded_bundle.proof[0] ^= 1;
    txdata = PrecomputedTransactionData{};
    txdata.Init(tx_proof, {}, /*force=*/true);
    BOOST_CHECK(ComputeCTVHash(tx_proof, 0, txdata) != baseline);
}

BOOST_AUTO_TEST_CASE(ctv_hash_commits_to_v2_shielded_bundle_bytes)
{
    CMutableTransaction tx;
    tx.version = 2;
    tx.nLockTime = 0;
    tx.vin.resize(1);
    tx.vin[0].nSequence = 7;
    tx.vout.resize(1);
    tx.vout[0].nValue = 10'000;
    tx.vout[0].scriptPubKey = CScript{} << OP_1;
    tx.shielded_bundle = BuildCTVV2ShieldedBundle();

    PrecomputedTransactionData txdata;
    txdata.Init(tx, {}, /*force=*/true);
    BOOST_REQUIRE(txdata.m_ctv_has_shielded_bundle);
    BOOST_CHECK_EQUAL(txdata.m_ctv_shielded_bundle_hash, ComputeShieldedBundleCtvHash(tx.shielded_bundle));
    const uint256 baseline = ComputeCTVHash(tx, 0, txdata);

    CMutableTransaction tx_payload = tx;
    tx_payload.shielded_bundle.v2_bundle->proof_payload[0] ^= 0x01;
    txdata = PrecomputedTransactionData{};
    txdata.Init(tx_payload, {}, /*force=*/true);
    BOOST_CHECK(ComputeCTVHash(tx_payload, 0, txdata) != baseline);

    CMutableTransaction tx_output = tx;
    auto& output_payload =
        std::get<shielded::v2::SendPayload>(tx_output.shielded_bundle.v2_bundle->payload);
    BOOST_REQUIRE(output_payload.outputs[0].smile_account.has_value());
    output_payload.outputs[0].smile_account->public_coin.t_msg[0].coeffs[0] += 1;
    output_payload.outputs[0].note_commitment =
        smile2::ComputeCompactPublicAccountHash(*output_payload.outputs[0].smile_account);
    tx_output.shielded_bundle.v2_bundle->header.payload_digest =
        shielded::v2::ComputeSendPayloadDigest(output_payload);
    txdata = PrecomputedTransactionData{};
    txdata.Init(tx_output, {}, /*force=*/true);
    BOOST_CHECK(ComputeCTVHash(tx_output, 0, txdata) != baseline);
}

BOOST_AUTO_TEST_CASE(ctv_roundtrip_happy_path_p2mr)
{
    const uint256 ctv_hash = ComputeCTVHashForTemplateSpend();
    const std::vector<unsigned char> leaf_script = BuildCTVOnlyLeafScript(ctv_hash);
    const uint256 merkle_root = ComputeP2MRMerkleRoot({ComputeP2MRLeafHash(P2MR_LEAF_VERSION, leaf_script)});
    P2MRSpendContext ctx{BuildP2MROutput(merkle_root)};

    CScriptWitness witness;
    witness.stack = {leaf_script, {P2MR_LEAF_VERSION}};

    ScriptError err{SCRIPT_ERR_UNKNOWN_ERROR};
    BOOST_CHECK(VerifyP2MRSpend(ctx, witness, err));
    BOOST_CHECK_EQUAL(err, SCRIPT_ERR_OK);
}

BOOST_AUTO_TEST_CASE(ctv_mismatch_outputs_fails)
{
    const uint256 ctv_hash = ComputeCTVHashForTemplateSpend();
    const std::vector<unsigned char> leaf_script = BuildCTVOnlyLeafScript(ctv_hash);
    const uint256 merkle_root = ComputeP2MRMerkleRoot({ComputeP2MRLeafHash(P2MR_LEAF_VERSION, leaf_script)});
    P2MRSpendContext ctx{BuildP2MROutput(merkle_root)};

    ctx.tx_spend.vout[0].nValue -= 1;
    ctx.txdata = PrecomputedTransactionData{};
    ctx.txdata.Init(ctx.tx_spend, {ctx.tx_credit.vout.at(0)}, /*force=*/true);

    CScriptWitness witness;
    witness.stack = {leaf_script, {P2MR_LEAF_VERSION}};

    ScriptError err{SCRIPT_ERR_UNKNOWN_ERROR};
    BOOST_CHECK(!VerifyP2MRSpend(ctx, witness, err));
    BOOST_CHECK_EQUAL(err, SCRIPT_ERR_CTV_HASH_MISMATCH);
}

BOOST_AUTO_TEST_CASE(ctv_mismatch_locktime_fails)
{
    const uint256 ctv_hash = ComputeCTVHashForTemplateSpend();
    const std::vector<unsigned char> leaf_script = BuildCTVOnlyLeafScript(ctv_hash);
    const uint256 merkle_root = ComputeP2MRMerkleRoot({ComputeP2MRLeafHash(P2MR_LEAF_VERSION, leaf_script)});
    P2MRSpendContext ctx{BuildP2MROutput(merkle_root)};

    ctx.tx_spend.nLockTime = 42;
    ctx.txdata = PrecomputedTransactionData{};
    ctx.txdata.Init(ctx.tx_spend, {ctx.tx_credit.vout.at(0)}, /*force=*/true);

    CScriptWitness witness;
    witness.stack = {leaf_script, {P2MR_LEAF_VERSION}};

    ScriptError err{SCRIPT_ERR_UNKNOWN_ERROR};
    BOOST_CHECK(!VerifyP2MRSpend(ctx, witness, err));
    BOOST_CHECK_EQUAL(err, SCRIPT_ERR_CTV_HASH_MISMATCH);
}

BOOST_AUTO_TEST_CASE(ctv_mismatch_input_index_fails)
{
    const uint256 ctv_hash = ComputeCTVHashForInputIndexOneTemplate();
    const std::vector<unsigned char> leaf_script = BuildCTVOnlyLeafScript(ctv_hash);
    const uint256 merkle_root = ComputeP2MRMerkleRoot({ComputeP2MRLeafHash(P2MR_LEAF_VERSION, leaf_script)});
    P2MRSpendContext ctx{BuildP2MROutput(merkle_root)};

    CScriptWitness witness;
    witness.stack = {leaf_script, {P2MR_LEAF_VERSION}};

    ScriptError err{SCRIPT_ERR_UNKNOWN_ERROR};
    BOOST_CHECK(!VerifyP2MRSpend(ctx, witness, err));
    BOOST_CHECK_EQUAL(err, SCRIPT_ERR_CTV_HASH_MISMATCH);
}

BOOST_AUTO_TEST_CASE(ctv_cleanstack_no_pop_behavior)
{
    const StubCTVChecker checker;
    std::vector<std::vector<unsigned char>> stack;
    ScriptExecutionData execdata;
    ScriptError err{SCRIPT_ERR_UNKNOWN_ERROR};

    const std::vector<unsigned char> hash32(32, 0xAB);
    CScript script;
    script << hash32 << OP_CHECKTEMPLATEVERIFY;

    BOOST_REQUIRE(EvalScript(stack, script, SCRIPT_VERIFY_CHECKTEMPLATEVERIFY, checker, SigVersion::P2MR, execdata, &err));
    BOOST_REQUIRE_EQUAL(stack.size(), 1U);
    BOOST_CHECK(stack.back() == hash32);
}

BOOST_AUTO_TEST_CASE(ctv_non_32_byte_arg_fails_20_bytes)
{
    const StubCTVChecker checker;
    std::vector<std::vector<unsigned char>> stack{std::vector<unsigned char>(20, 0x01)};
    ScriptExecutionData execdata;
    ScriptError err{SCRIPT_ERR_UNKNOWN_ERROR};
    const CScript script{OP_CHECKTEMPLATEVERIFY};

    BOOST_CHECK(!EvalScript(stack, script, SCRIPT_VERIFY_CHECKTEMPLATEVERIFY, checker, SigVersion::P2MR, execdata, &err));
    BOOST_CHECK_EQUAL(err, SCRIPT_ERR_CTV_HASH_SIZE);
}

BOOST_AUTO_TEST_CASE(ctv_non_32_byte_arg_fails_33_bytes)
{
    const StubCTVChecker checker;
    std::vector<std::vector<unsigned char>> stack{std::vector<unsigned char>(33, 0x01)};
    ScriptExecutionData execdata;
    ScriptError err{SCRIPT_ERR_UNKNOWN_ERROR};
    const CScript script{OP_CHECKTEMPLATEVERIFY};

    BOOST_CHECK(!EvalScript(stack, script, SCRIPT_VERIFY_CHECKTEMPLATEVERIFY, checker, SigVersion::P2MR, execdata, &err));
    BOOST_CHECK_EQUAL(err, SCRIPT_ERR_CTV_HASH_SIZE);
}

BOOST_AUTO_TEST_CASE(ctv_non_32_byte_arg_fails_empty)
{
    const StubCTVChecker checker;
    std::vector<std::vector<unsigned char>> stack{std::vector<unsigned char>()};
    ScriptExecutionData execdata;
    ScriptError err{SCRIPT_ERR_UNKNOWN_ERROR};
    const CScript script{OP_CHECKTEMPLATEVERIFY};

    BOOST_CHECK(!EvalScript(stack, script, SCRIPT_VERIFY_CHECKTEMPLATEVERIFY, checker, SigVersion::P2MR, execdata, &err));
    BOOST_CHECK_EQUAL(err, SCRIPT_ERR_CTV_HASH_SIZE);
}

BOOST_AUTO_TEST_CASE(ctv_empty_stack_fails)
{
    const StubCTVChecker checker;
    std::vector<std::vector<unsigned char>> stack;
    ScriptExecutionData execdata;
    ScriptError err{SCRIPT_ERR_UNKNOWN_ERROR};
    const CScript script{OP_CHECKTEMPLATEVERIFY};

    BOOST_CHECK(!EvalScript(stack, script, SCRIPT_VERIFY_CHECKTEMPLATEVERIFY, checker, SigVersion::P2MR, execdata, &err));
    BOOST_CHECK_EQUAL(err, SCRIPT_ERR_INVALID_STACK_OPERATION);
}

BOOST_AUTO_TEST_CASE(ctv_hash_differs_by_input_index)
{
    CMutableTransaction tx;
    tx.version = 2;
    tx.nLockTime = 3;
    tx.vin.resize(2);
    tx.vin[0].nSequence = 1;
    tx.vin[1].nSequence = 2;
    tx.vout.resize(1);
    tx.vout[0].nValue = 5'000;
    tx.vout[0].scriptPubKey = CScript{} << OP_1;

    PrecomputedTransactionData txdata;
    txdata.Init(tx, {}, /*force=*/true);

    const uint256 hash0 = ComputeCTVHash(tx, 0, txdata);
    const uint256 hash1 = ComputeCTVHash(tx, 1, txdata);
    BOOST_CHECK(hash0 != hash1);
}

BOOST_AUTO_TEST_CASE(ctv_flag_unset_behaves_as_nop)
{
    const StubCTVChecker checker;
    std::vector<unsigned char> hash32(32, 0x11);
    std::vector<std::vector<unsigned char>> stack{hash32};
    ScriptExecutionData execdata;
    ScriptError err{SCRIPT_ERR_UNKNOWN_ERROR};
    const CScript script{OP_CHECKTEMPLATEVERIFY};

    BOOST_REQUIRE(EvalScript(stack, script, SCRIPT_VERIFY_NONE, checker, SigVersion::P2MR, execdata, &err));
    BOOST_REQUIRE_EQUAL(stack.size(), 1U);
    BOOST_CHECK(stack.back() == hash32);
}

BOOST_AUTO_TEST_CASE(ctv_flag_unset_with_discourage_nops_fails)
{
    const StubCTVChecker checker;
    std::vector<std::vector<unsigned char>> stack{std::vector<unsigned char>(32, 0x11)};
    ScriptExecutionData execdata;
    ScriptError err{SCRIPT_ERR_UNKNOWN_ERROR};
    const CScript script{OP_CHECKTEMPLATEVERIFY};

    BOOST_CHECK(!EvalScript(stack, script, SCRIPT_VERIFY_DISCOURAGE_UPGRADABLE_NOPS, checker, SigVersion::P2MR, execdata, &err));
    BOOST_CHECK_EQUAL(err, SCRIPT_ERR_DISCOURAGE_UPGRADABLE_NOPS);
}

BOOST_AUTO_TEST_CASE(ctv_flag_set_non_p2mr_context_is_nop)
{
    const StubCTVChecker checker;
    std::vector<unsigned char> hash32(32, 0x11);
    std::vector<std::vector<unsigned char>> stack{hash32};
    ScriptExecutionData execdata;
    ScriptError err{SCRIPT_ERR_UNKNOWN_ERROR};
    const CScript script{OP_CHECKTEMPLATEVERIFY};

    BOOST_REQUIRE(EvalScript(stack, script, SCRIPT_VERIFY_CHECKTEMPLATEVERIFY, checker, SigVersion::BASE, execdata, &err));
    BOOST_REQUIRE_EQUAL(stack.size(), 1U);
    BOOST_CHECK(stack.back() == hash32);
}

BOOST_AUTO_TEST_CASE(ctv_check_missing_txdata_fails_safely)
{
    CMutableTransaction tx;
    tx.vin.resize(1);
    tx.vout.resize(1);
    MutableTransactionSignatureChecker checker(&tx, /*nIn=*/0, /*amount=*/0, MissingDataBehavior::FAIL);
    const std::vector<unsigned char> hash32(32, 0x01);
    BOOST_CHECK(!checker.CheckCTVHash(hash32));
}

BOOST_AUTO_TEST_CASE(ctv_sequences_subhash_matches_manual)
{
    CMutableTransaction tx;
    tx.version = 2;
    tx.nLockTime = 9;
    tx.vin.resize(2);
    tx.vin[0].nSequence = 1;
    tx.vin[1].nSequence = 2;
    tx.vout.resize(1);
    tx.vout[0].nValue = 9'000;
    tx.vout[0].scriptPubKey = CScript{} << OP_1;

    PrecomputedTransactionData txdata;
    txdata.Init(tx, {}, /*force=*/true);

    HashWriter ss{};
    for (const auto& txin : tx.vin) {
        ss << txin.nSequence;
    }
    BOOST_CHECK_EQUAL(txdata.m_sequences_single_hash, ss.GetSHA256());
}

BOOST_AUTO_TEST_CASE(ctv_outputs_subhash_matches_manual)
{
    CMutableTransaction tx;
    tx.version = 2;
    tx.nLockTime = 9;
    tx.vin.resize(1);
    tx.vin[0].nSequence = 1;
    tx.vout.resize(2);
    tx.vout[0].nValue = 9'000;
    tx.vout[0].scriptPubKey = CScript{} << OP_1;
    tx.vout[1].nValue = 8'000;
    tx.vout[1].scriptPubKey = CScript{} << OP_0;

    PrecomputedTransactionData txdata;
    txdata.Init(tx, {}, /*force=*/true);

    HashWriter ss{};
    for (const auto& txout : tx.vout) {
        ss << txout;
    }
    BOOST_CHECK_EQUAL(txdata.m_outputs_single_hash, ss.GetSHA256());
}

BOOST_AUTO_TEST_CASE(ctv_scriptsigs_subhash_matches_manual)
{
    CMutableTransaction tx;
    tx.version = 2;
    tx.nLockTime = 9;
    tx.vin.resize(2);
    tx.vin[0].scriptSig = CScript{} << OP_1;
    tx.vin[0].nSequence = 1;
    tx.vin[1].scriptSig = CScript{} << std::vector<unsigned char>{0xCA, 0xFE};
    tx.vin[1].nSequence = 2;
    tx.vout.resize(1);
    tx.vout[0].nValue = 9'000;
    tx.vout[0].scriptPubKey = CScript{} << OP_1;

    PrecomputedTransactionData txdata;
    txdata.Init(tx, {}, /*force=*/true);

    HashWriter ss{};
    for (const auto& txin : tx.vin) {
        ss << txin.scriptSig;
    }
    BOOST_CHECK_EQUAL(txdata.m_ctv_scriptsigs_hash, ss.GetSHA256());
}

BOOST_AUTO_TEST_CASE(ctv_precompute_sets_ready_flag)
{
    CMutableTransaction tx;
    tx.version = 2;
    tx.nLockTime = 0;
    tx.vin.resize(1);
    tx.vin[0].nSequence = 1;
    tx.vout.resize(1);
    tx.vout[0].nValue = 1'000;
    tx.vout[0].scriptPubKey = CScript{} << OP_1;

    PrecomputedTransactionData txdata;
    txdata.Init(tx, {}, /*force=*/true);
    BOOST_CHECK(txdata.m_ctv_ready);
    BOOST_CHECK(!txdata.m_ctv_has_shielded_bundle);
    BOOST_CHECK(txdata.m_ctv_shielded_bundle_hash.IsNull());
}

BOOST_AUTO_TEST_CASE(ctv_and_checksig_combined_leaf_succeeds)
{
    CPQKey key;
    key.MakeNewKey(PQAlgorithm::ML_DSA_44);
    BOOST_REQUIRE(key.IsValid());

    const uint256 ctv_hash = ComputeCTVHashForTemplateSpend();
    const std::vector<unsigned char> leaf_script = BuildCTVChecksigLeafScript(ctv_hash, PQAlgorithm::ML_DSA_44, key.GetPubKey());
    const uint256 merkle_root = ComputeP2MRMerkleRoot({ComputeP2MRLeafHash(P2MR_LEAF_VERSION, leaf_script)});
    P2MRSpendContext ctx{BuildP2MROutput(merkle_root)};

    const auto sighash = ComputeP2MRSighash(ctx, leaf_script);
    BOOST_REQUIRE(sighash.has_value());

    std::vector<unsigned char> signature;
    BOOST_REQUIRE(key.Sign(*sighash, signature));

    CScriptWitness witness;
    witness.stack = {signature, leaf_script, {P2MR_LEAF_VERSION}};

    ScriptError err{SCRIPT_ERR_UNKNOWN_ERROR};
    BOOST_CHECK(VerifyP2MRSpend(ctx, witness, err));
    BOOST_CHECK_EQUAL(err, SCRIPT_ERR_OK);
}

BOOST_AUTO_TEST_CASE(csv_multisig_leaf_succeeds_when_sequence_is_met)
{
    CPQKey key1;
    key1.MakeNewKey(PQAlgorithm::ML_DSA_44);
    BOOST_REQUIRE(key1.IsValid());
    CPQKey key2;
    key2.MakeNewKey(PQAlgorithm::SLH_DSA_128S);
    BOOST_REQUIRE(key2.IsValid());

    const std::vector<unsigned char> leaf_script = BuildP2MRCSVMultisigScript(
        /*sequence=*/7,
        /*threshold=*/1,
        {
            {PQAlgorithm::ML_DSA_44, key1.GetPubKey()},
            {PQAlgorithm::SLH_DSA_128S, key2.GetPubKey()},
        });
    BOOST_REQUIRE(!leaf_script.empty());
    const uint256 merkle_root = ComputeP2MRMerkleRoot({ComputeP2MRLeafHash(P2MR_LEAF_VERSION, leaf_script)});
    P2MRSpendContext ctx{BuildP2MROutput(merkle_root)};
    ctx.tx_spend.version = 2;
    ctx.tx_spend.vin.at(0).nSequence = 7;
    ctx.txdata = PrecomputedTransactionData{};
    ctx.txdata.Init(ctx.tx_spend, {ctx.tx_credit.vout.at(0)}, /*force=*/true);

    const std::vector<CPQKey> signer_keys{key1, key2};
    const auto witness = BuildSignedMultisigLeafP2MRWitness(ctx, signer_keys, /*threshold=*/1, leaf_script);
    BOOST_REQUIRE(witness.has_value());

    ScriptError err{SCRIPT_ERR_UNKNOWN_ERROR};
    BOOST_CHECK(VerifyP2MRSpendWithFlags(ctx, *witness, P2MR_SCRIPT_FLAGS | SCRIPT_VERIFY_CHECKSEQUENCEVERIFY, err));
    BOOST_CHECK_EQUAL(err, SCRIPT_ERR_OK);
}

BOOST_AUTO_TEST_CASE(csv_multisig_leaf_fails_when_sequence_is_unmet)
{
    CPQKey key1;
    key1.MakeNewKey(PQAlgorithm::ML_DSA_44);
    BOOST_REQUIRE(key1.IsValid());
    CPQKey key2;
    key2.MakeNewKey(PQAlgorithm::SLH_DSA_128S);
    BOOST_REQUIRE(key2.IsValid());

    const std::vector<unsigned char> leaf_script = BuildP2MRCSVMultisigScript(
        /*sequence=*/7,
        /*threshold=*/1,
        {
            {PQAlgorithm::ML_DSA_44, key1.GetPubKey()},
            {PQAlgorithm::SLH_DSA_128S, key2.GetPubKey()},
        });
    BOOST_REQUIRE(!leaf_script.empty());
    const uint256 merkle_root = ComputeP2MRMerkleRoot({ComputeP2MRLeafHash(P2MR_LEAF_VERSION, leaf_script)});
    P2MRSpendContext ctx{BuildP2MROutput(merkle_root)};
    ctx.tx_spend.version = 2;
    ctx.tx_spend.vin.at(0).nSequence = 6;
    ctx.txdata = PrecomputedTransactionData{};
    ctx.txdata.Init(ctx.tx_spend, {ctx.tx_credit.vout.at(0)}, /*force=*/true);

    const std::vector<CPQKey> signer_keys{key1, key2};
    const auto witness = BuildSignedMultisigLeafP2MRWitness(ctx, signer_keys, /*threshold=*/1, leaf_script);
    BOOST_REQUIRE(witness.has_value());

    ScriptError err{SCRIPT_ERR_UNKNOWN_ERROR};
    BOOST_CHECK(!VerifyP2MRSpendWithFlags(ctx, *witness, P2MR_SCRIPT_FLAGS | SCRIPT_VERIFY_CHECKSEQUENCEVERIFY, err));
    BOOST_CHECK_EQUAL(err, SCRIPT_ERR_UNSATISFIED_LOCKTIME);
}

BOOST_AUTO_TEST_CASE(csfs_mldsa_happy_path)
{
    CPQKey key;
    key.MakeNewKey(PQAlgorithm::ML_DSA_44);
    BOOST_REQUIRE(key.IsValid());
    const std::vector<unsigned char> msg{0xAA, 0xBB, 0xCC};
    const std::vector<unsigned char> sig = CreateCSFSSignature(key, msg);
    const std::vector<unsigned char> script_bytes = BuildP2MRCSFSScript(PQAlgorithm::ML_DSA_44, key.GetPubKey());
    const CScript script(script_bytes.begin(), script_bytes.end());

    std::vector<std::vector<unsigned char>> stack{sig, msg};
    ScriptExecutionData execdata;
    execdata.m_validation_weight_left_init = true;
    execdata.m_validation_weight_left = 10 * VALIDATION_WEIGHT_PER_MLDSA_SIGOP;
    ScriptError err{SCRIPT_ERR_UNKNOWN_ERROR};

    BOOST_REQUIRE(EvalP2MRScript(stack, script, SCRIPT_VERIFY_NONE, BaseSignatureChecker{}, execdata, err));
    BOOST_CHECK_EQUAL(stack.size(), 1U);
    BOOST_CHECK(stack.back() == std::vector<unsigned char>({1}));
}

BOOST_AUTO_TEST_CASE(csfs_slhdsa_happy_path)
{
    CPQKey key;
    key.MakeNewKey(PQAlgorithm::SLH_DSA_128S);
    BOOST_REQUIRE(key.IsValid());
    const std::vector<unsigned char> msg{0x11, 0x22};
    const std::vector<unsigned char> sig = CreateCSFSSignature(key, msg);
    const std::vector<unsigned char> script_bytes = BuildP2MRCSFSScript(PQAlgorithm::SLH_DSA_128S, key.GetPubKey());
    const CScript script(script_bytes.begin(), script_bytes.end());

    std::vector<std::vector<unsigned char>> stack{sig, msg};
    ScriptExecutionData execdata;
    execdata.m_validation_weight_left_init = true;
    execdata.m_validation_weight_left = 10 * VALIDATION_WEIGHT_PER_SLHDSA_SIGOP;
    ScriptError err{SCRIPT_ERR_UNKNOWN_ERROR};

    BOOST_REQUIRE(EvalP2MRScript(stack, script, SCRIPT_VERIFY_NONE, BaseSignatureChecker{}, execdata, err));
    BOOST_CHECK_EQUAL(stack.size(), 1U);
    BOOST_CHECK(stack.back() == std::vector<unsigned char>({1}));
}

BOOST_AUTO_TEST_CASE(csfs_slhdsa_corrupted_signature_pushes_false)
{
    CPQKey key;
    key.MakeNewKey(PQAlgorithm::SLH_DSA_128S);
    BOOST_REQUIRE(key.IsValid());
    const std::vector<unsigned char> msg{0x40, 0x41, 0x42};
    std::vector<unsigned char> sig = CreateCSFSSignature(key, msg);
    sig[0] ^= 1;
    const std::vector<unsigned char> script_bytes = BuildP2MRCSFSScript(PQAlgorithm::SLH_DSA_128S, key.GetPubKey());
    const CScript script(script_bytes.begin(), script_bytes.end());

    std::vector<std::vector<unsigned char>> stack{sig, msg};
    ScriptExecutionData execdata;
    execdata.m_validation_weight_left_init = true;
    execdata.m_validation_weight_left = 10 * VALIDATION_WEIGHT_PER_SLHDSA_SIGOP;
    ScriptError err{SCRIPT_ERR_UNKNOWN_ERROR};

    BOOST_REQUIRE(EvalP2MRScript(stack, script, SCRIPT_VERIFY_NONE, BaseSignatureChecker{}, execdata, err));
    BOOST_CHECK_EQUAL(stack.size(), 1U);
    BOOST_CHECK(stack.back().empty());
}

BOOST_AUTO_TEST_CASE(csfs_slhdsa_empty_signature_pushes_false_and_does_not_consume_weight)
{
    CPQKey key;
    key.MakeNewKey(PQAlgorithm::SLH_DSA_128S);
    BOOST_REQUIRE(key.IsValid());
    const std::vector<unsigned char> msg{0x01};
    const std::vector<unsigned char> script_bytes = BuildP2MRCSFSScript(PQAlgorithm::SLH_DSA_128S, key.GetPubKey());
    const CScript script(script_bytes.begin(), script_bytes.end());

    std::vector<std::vector<unsigned char>> stack{{}, msg};
    ScriptExecutionData execdata;
    execdata.m_validation_weight_left_init = true;
    execdata.m_validation_weight_left = 1337;
    ScriptError err{SCRIPT_ERR_UNKNOWN_ERROR};

    BOOST_REQUIRE(EvalP2MRScript(stack, script, SCRIPT_VERIFY_NONE, BaseSignatureChecker{}, execdata, err));
    BOOST_CHECK_EQUAL(stack.size(), 1U);
    BOOST_CHECK(stack.back().empty());
    BOOST_CHECK_EQUAL(execdata.m_validation_weight_left, 1337);
}

BOOST_AUTO_TEST_CASE(csfs_slhdsa_nullfail_nonempty_failed_sig_errors)
{
    CPQKey key;
    key.MakeNewKey(PQAlgorithm::SLH_DSA_128S);
    BOOST_REQUIRE(key.IsValid());
    const std::vector<unsigned char> msg{0x99, 0x98};
    std::vector<unsigned char> sig = CreateCSFSSignature(key, msg);
    sig.back() ^= 0x80;
    const std::vector<unsigned char> script_bytes = BuildP2MRCSFSScript(PQAlgorithm::SLH_DSA_128S, key.GetPubKey());
    const CScript script(script_bytes.begin(), script_bytes.end());

    std::vector<std::vector<unsigned char>> stack{sig, msg};
    ScriptExecutionData execdata;
    execdata.m_validation_weight_left_init = true;
    execdata.m_validation_weight_left = 10 * VALIDATION_WEIGHT_PER_SLHDSA_SIGOP;
    ScriptError err{SCRIPT_ERR_UNKNOWN_ERROR};

    BOOST_CHECK(!EvalP2MRScript(stack, script, SCRIPT_VERIFY_NULLFAIL, BaseSignatureChecker{}, execdata, err));
    BOOST_CHECK_EQUAL(err, SCRIPT_ERR_SIG_SLHDSA);
}

BOOST_AUTO_TEST_CASE(csfs_corrupted_signature_pushes_false)
{
    CPQKey key;
    key.MakeNewKey(PQAlgorithm::ML_DSA_44);
    BOOST_REQUIRE(key.IsValid());
    const std::vector<unsigned char> msg{0x40, 0x41, 0x42};
    std::vector<unsigned char> sig = CreateCSFSSignature(key, msg);
    sig[0] ^= 1;
    const std::vector<unsigned char> script_bytes = BuildP2MRCSFSScript(PQAlgorithm::ML_DSA_44, key.GetPubKey());
    const CScript script(script_bytes.begin(), script_bytes.end());

    std::vector<std::vector<unsigned char>> stack{sig, msg};
    ScriptExecutionData execdata;
    execdata.m_validation_weight_left_init = true;
    execdata.m_validation_weight_left = 10 * VALIDATION_WEIGHT_PER_MLDSA_SIGOP;
    ScriptError err{SCRIPT_ERR_UNKNOWN_ERROR};

    BOOST_REQUIRE(EvalP2MRScript(stack, script, SCRIPT_VERIFY_NONE, BaseSignatureChecker{}, execdata, err));
    BOOST_CHECK_EQUAL(stack.size(), 1U);
    BOOST_CHECK(stack.back().empty());
}

BOOST_AUTO_TEST_CASE(csfs_empty_signature_pushes_false_and_does_not_consume_weight)
{
    CPQKey key;
    key.MakeNewKey(PQAlgorithm::ML_DSA_44);
    BOOST_REQUIRE(key.IsValid());
    const std::vector<unsigned char> msg{0x01};
    const std::vector<unsigned char> script_bytes = BuildP2MRCSFSScript(PQAlgorithm::ML_DSA_44, key.GetPubKey());
    const CScript script(script_bytes.begin(), script_bytes.end());

    std::vector<std::vector<unsigned char>> stack{{}, msg};
    ScriptExecutionData execdata;
    execdata.m_validation_weight_left_init = true;
    execdata.m_validation_weight_left = 1337;
    ScriptError err{SCRIPT_ERR_UNKNOWN_ERROR};

    BOOST_REQUIRE(EvalP2MRScript(stack, script, SCRIPT_VERIFY_NONE, BaseSignatureChecker{}, execdata, err));
    BOOST_CHECK_EQUAL(stack.size(), 1U);
    BOOST_CHECK(stack.back().empty());
    BOOST_CHECK_EQUAL(execdata.m_validation_weight_left, 1337);
}

BOOST_AUTO_TEST_CASE(csfs_nullfail_nonempty_failed_sig_errors)
{
    CPQKey key;
    key.MakeNewKey(PQAlgorithm::ML_DSA_44);
    BOOST_REQUIRE(key.IsValid());
    const std::vector<unsigned char> msg{0x99, 0x98};
    std::vector<unsigned char> sig = CreateCSFSSignature(key, msg);
    sig.back() ^= 0x80;
    const std::vector<unsigned char> script_bytes = BuildP2MRCSFSScript(PQAlgorithm::ML_DSA_44, key.GetPubKey());
    const CScript script(script_bytes.begin(), script_bytes.end());

    std::vector<std::vector<unsigned char>> stack{sig, msg};
    ScriptExecutionData execdata;
    execdata.m_validation_weight_left_init = true;
    execdata.m_validation_weight_left = 10 * VALIDATION_WEIGHT_PER_MLDSA_SIGOP;
    ScriptError err{SCRIPT_ERR_UNKNOWN_ERROR};

    BOOST_CHECK(!EvalP2MRScript(stack, script, SCRIPT_VERIFY_NULLFAIL, BaseSignatureChecker{}, execdata, err));
    BOOST_CHECK_EQUAL(err, SCRIPT_ERR_SIG_MLDSA);
}

BOOST_AUTO_TEST_CASE(csfs_stack_underflow_fails)
{
    ScriptExecutionData execdata;
    execdata.m_validation_weight_left_init = true;
    execdata.m_validation_weight_left = 1000;
    ScriptError err{SCRIPT_ERR_UNKNOWN_ERROR};
    const CScript script{OP_CHECKSIGFROMSTACK};

    std::vector<std::vector<unsigned char>> stack{};
    BOOST_CHECK(!EvalScript(stack, script, SCRIPT_VERIFY_NONE, BaseSignatureChecker{}, SigVersion::P2MR, execdata, &err));
    BOOST_CHECK_EQUAL(err, SCRIPT_ERR_INVALID_STACK_OPERATION);

    std::vector<std::vector<unsigned char>> stack2{{0x01}, {0x02}};
    err = SCRIPT_ERR_UNKNOWN_ERROR;
    BOOST_CHECK(!EvalScript(stack2, script, SCRIPT_VERIFY_NONE, BaseSignatureChecker{}, SigVersion::P2MR, execdata, &err));
    BOOST_CHECK_EQUAL(err, SCRIPT_ERR_INVALID_STACK_OPERATION);
}

BOOST_AUTO_TEST_CASE(csfs_pubkey_size_rejections)
{
    ScriptExecutionData execdata;
    execdata.m_validation_weight_left_init = true;
    execdata.m_validation_weight_left = 1000;
    ScriptError err{SCRIPT_ERR_UNKNOWN_ERROR};
    const CScript script{OP_CHECKSIGFROMSTACK};

    std::vector<std::vector<unsigned char>> bad33{std::vector<unsigned char>(MLDSA44_SIGNATURE_SIZE, 0x01), {0x01}, std::vector<unsigned char>(33, 0x11)};
    BOOST_CHECK(!EvalScript(bad33, script, SCRIPT_VERIFY_NONE, BaseSignatureChecker{}, SigVersion::P2MR, execdata, &err));
    BOOST_CHECK_EQUAL(err, SCRIPT_ERR_PQ_PUBKEY_SIZE);

    std::vector<std::vector<unsigned char>> bad0{std::vector<unsigned char>(MLDSA44_SIGNATURE_SIZE, 0x01), {0x01}, {}};
    err = SCRIPT_ERR_UNKNOWN_ERROR;
    BOOST_CHECK(!EvalScript(bad0, script, SCRIPT_VERIFY_NONE, BaseSignatureChecker{}, SigVersion::P2MR, execdata, &err));
    BOOST_CHECK_EQUAL(err, SCRIPT_ERR_PQ_PUBKEY_SIZE);

    std::vector<std::vector<unsigned char>> bad1311{std::vector<unsigned char>(MLDSA44_SIGNATURE_SIZE, 0x01), {0x01}, std::vector<unsigned char>(MLDSA44_PUBKEY_SIZE - 1, 0x11)};
    err = SCRIPT_ERR_UNKNOWN_ERROR;
    BOOST_CHECK(!EvalScript(bad1311, script, SCRIPT_VERIFY_NONE, BaseSignatureChecker{}, SigVersion::P2MR, execdata, &err));
    BOOST_CHECK_EQUAL(err, SCRIPT_ERR_PQ_PUBKEY_SIZE);
}

BOOST_AUTO_TEST_CASE(csfs_tagged_hash_domain_separation)
{
    const std::vector<unsigned char> msg{0xDE, 0xAD, 0xBE, 0xEF};

    HashWriter tagged = HASHER_CSFS;
    tagged.write(MakeByteSpan(msg));
    const uint256 tagged_hash = tagged.GetSHA256();

    const uint256 plain_hash = Hash(msg);

    BOOST_CHECK(tagged_hash != plain_hash);
}

BOOST_AUTO_TEST_CASE(csfs_write_vs_stream_operator_hashing_differs)
{
    const std::vector<unsigned char> msg{0x00, 0x11, 0x22};

    HashWriter via_write = HASHER_CSFS;
    via_write.write(MakeByteSpan(msg));
    const uint256 hash_write = via_write.GetSHA256();

    HashWriter via_stream = HASHER_CSFS;
    via_stream << msg;
    const uint256 hash_stream = via_stream.GetSHA256();

    BOOST_CHECK(hash_write != hash_stream);
}

BOOST_AUTO_TEST_CASE(csfs_does_not_use_checkpqsignature_path)
{
    CPQKey key;
    key.MakeNewKey(PQAlgorithm::ML_DSA_44);
    BOOST_REQUIRE(key.IsValid());
    const std::vector<unsigned char> msg{0x14, 0x15};
    std::vector<unsigned char> sig = CreateCSFSSignature(key, msg);
    sig[0] ^= 0x55;
    const std::vector<unsigned char> script_bytes = BuildP2MRCSFSScript(PQAlgorithm::ML_DSA_44, key.GetPubKey());
    const CScript script(script_bytes.begin(), script_bytes.end());

    std::vector<std::vector<unsigned char>> stack{sig, msg};
    ScriptExecutionData execdata;
    execdata.m_validation_weight_left_init = true;
    execdata.m_validation_weight_left = 10 * VALIDATION_WEIGHT_PER_MLDSA_SIGOP;
    ScriptError err{SCRIPT_ERR_UNKNOWN_ERROR};
    const AlwaysTruePQChecker checker;

    BOOST_REQUIRE(EvalP2MRScript(stack, script, SCRIPT_VERIFY_NONE, checker, execdata, err));
    BOOST_CHECK_EQUAL(stack.size(), 1U);
    BOOST_CHECK(stack.back().empty());
}

BOOST_AUTO_TEST_CASE(csfs_sigversion_gating_bad_opcode)
{
    ScriptExecutionData execdata;
    execdata.m_validation_weight_left_init = true;
    execdata.m_validation_weight_left = 1000;
    ScriptError err{SCRIPT_ERR_UNKNOWN_ERROR};
    const CScript script{OP_CHECKSIGFROMSTACK};

    std::vector<std::vector<unsigned char>> stack{{0x01}, {0x02}, {0x03}};
    BOOST_CHECK(!EvalScript(stack, script, SCRIPT_VERIFY_NONE, BaseSignatureChecker{}, SigVersion::BASE, execdata, &err));
    BOOST_CHECK_EQUAL(err, SCRIPT_ERR_BAD_OPCODE);

    err = SCRIPT_ERR_UNKNOWN_ERROR;
    stack = {{0x01}, {0x02}, {0x03}};
    BOOST_CHECK(!EvalScript(stack, script, SCRIPT_VERIFY_NONE, BaseSignatureChecker{}, SigVersion::WITNESS_V0, execdata, &err));
    BOOST_CHECK_EQUAL(err, SCRIPT_ERR_BAD_OPCODE);
}

BOOST_AUTO_TEST_CASE(csfs_message_size_boundaries)
{
    CPQKey key;
    key.MakeNewKey(PQAlgorithm::ML_DSA_44);
    BOOST_REQUIRE(key.IsValid());
    const std::vector<unsigned char> script_bytes = BuildP2MRCSFSScript(PQAlgorithm::ML_DSA_44, key.GetPubKey());
    const CScript script(script_bytes.begin(), script_bytes.end());

    for (const size_t msg_len : {size_t{520}, size_t{0}, size_t{521}}) {
        std::vector<unsigned char> msg(msg_len, 0x77);
        const std::vector<unsigned char> sig = CreateCSFSSignature(key, msg);
        std::vector<std::vector<unsigned char>> stack{sig, msg};
        ScriptExecutionData execdata;
        execdata.m_validation_weight_left_init = true;
        execdata.m_validation_weight_left = 10 * VALIDATION_WEIGHT_PER_MLDSA_SIGOP;
        ScriptError err{SCRIPT_ERR_UNKNOWN_ERROR};
        BOOST_REQUIRE(EvalP2MRScript(stack, script, SCRIPT_VERIFY_NONE, BaseSignatureChecker{}, execdata, err));
        BOOST_CHECK_EQUAL(stack.size(), 1U);
        BOOST_CHECK(stack.back() == std::vector<unsigned char>({1}));
    }
}

BOOST_AUTO_TEST_CASE(csfs_signature_size_enforced_exactly)
{
    CPQKey mldsa;
    mldsa.MakeNewKey(PQAlgorithm::ML_DSA_44);
    BOOST_REQUIRE(mldsa.IsValid());
    const std::vector<unsigned char> msg{0x22, 0x23};
    const std::vector<unsigned char> mldsa_script_bytes = BuildP2MRCSFSScript(PQAlgorithm::ML_DSA_44, mldsa.GetPubKey());
    const CScript mldsa_script(mldsa_script_bytes.begin(), mldsa_script_bytes.end());

    std::vector<unsigned char> mldsa_plus_one = CreateCSFSSignature(mldsa, msg);
    mldsa_plus_one.push_back(SIGHASH_DEFAULT);
    std::vector<std::vector<unsigned char>> stack{mldsa_plus_one, msg};
    ScriptExecutionData execdata;
    execdata.m_validation_weight_left_init = true;
    execdata.m_validation_weight_left = 10 * VALIDATION_WEIGHT_PER_MLDSA_SIGOP;
    ScriptError err{SCRIPT_ERR_UNKNOWN_ERROR};
    BOOST_CHECK(!EvalP2MRScript(stack, mldsa_script, SCRIPT_VERIFY_NONE, BaseSignatureChecker{}, execdata, err));
    BOOST_CHECK_EQUAL(err, SCRIPT_ERR_SIG_MLDSA);

    std::vector<std::vector<unsigned char>> wrong_size{std::vector<unsigned char>(100, 0x01), msg};
    err = SCRIPT_ERR_UNKNOWN_ERROR;
    BOOST_CHECK(!EvalP2MRScript(wrong_size, mldsa_script, SCRIPT_VERIFY_NONE, BaseSignatureChecker{}, execdata, err));
    BOOST_CHECK_EQUAL(err, SCRIPT_ERR_SIG_MLDSA);

    CPQKey slh;
    slh.MakeNewKey(PQAlgorithm::SLH_DSA_128S);
    BOOST_REQUIRE(slh.IsValid());
    const std::vector<unsigned char> slh_script_bytes = BuildP2MRCSFSScript(PQAlgorithm::SLH_DSA_128S, slh.GetPubKey());
    const CScript slh_script(slh_script_bytes.begin(), slh_script_bytes.end());
    std::vector<unsigned char> slh_plus_one = CreateCSFSSignature(slh, msg);
    slh_plus_one.push_back(SIGHASH_DEFAULT);
    std::vector<std::vector<unsigned char>> slh_stack{slh_plus_one, msg};
    ScriptExecutionData slh_exec;
    slh_exec.m_validation_weight_left_init = true;
    slh_exec.m_validation_weight_left = 10 * VALIDATION_WEIGHT_PER_SLHDSA_SIGOP;
    err = SCRIPT_ERR_UNKNOWN_ERROR;
    BOOST_CHECK(!EvalP2MRScript(slh_stack, slh_script, SCRIPT_VERIFY_NONE, BaseSignatureChecker{}, slh_exec, err));
    BOOST_CHECK_EQUAL(err, SCRIPT_ERR_SIG_SLHDSA);
}

BOOST_AUTO_TEST_CASE(csfs_validation_weight_accounting)
{
    CPQKey mldsa;
    mldsa.MakeNewKey(PQAlgorithm::ML_DSA_44);
    BOOST_REQUIRE(mldsa.IsValid());
    const std::vector<unsigned char> msg{0x51, 0x52};
    const std::vector<unsigned char> sig = CreateCSFSSignature(mldsa, msg);
    const std::vector<unsigned char> ml_script_bytes = BuildP2MRCSFSScript(PQAlgorithm::ML_DSA_44, mldsa.GetPubKey());
    const CScript ml_script(ml_script_bytes.begin(), ml_script_bytes.end());

    std::vector<std::vector<unsigned char>> stack{sig, msg};
    ScriptExecutionData execdata;
    execdata.m_validation_weight_left_init = true;
    execdata.m_validation_weight_left = VALIDATION_WEIGHT_PER_MLDSA_SIGOP + 99;
    ScriptError err{SCRIPT_ERR_UNKNOWN_ERROR};
    BOOST_REQUIRE(EvalP2MRScript(stack, ml_script, SCRIPT_VERIFY_NONE, BaseSignatureChecker{}, execdata, err));
    BOOST_CHECK_EQUAL(execdata.m_validation_weight_left, 99);

    CPQKey slh;
    slh.MakeNewKey(PQAlgorithm::SLH_DSA_128S);
    BOOST_REQUIRE(slh.IsValid());
    const std::vector<unsigned char> slh_msg{0x61, 0x62};
    const std::vector<unsigned char> slh_sig = CreateCSFSSignature(slh, slh_msg);
    const std::vector<unsigned char> slh_script_bytes = BuildP2MRCSFSScript(PQAlgorithm::SLH_DSA_128S, slh.GetPubKey());
    const CScript slh_script(slh_script_bytes.begin(), slh_script_bytes.end());
    std::vector<std::vector<unsigned char>> slh_stack{slh_sig, slh_msg};
    ScriptExecutionData slh_exec;
    slh_exec.m_validation_weight_left_init = true;
    slh_exec.m_validation_weight_left = VALIDATION_WEIGHT_PER_SLHDSA_SIGOP + 77;
    err = SCRIPT_ERR_UNKNOWN_ERROR;
    BOOST_REQUIRE(EvalP2MRScript(slh_stack, slh_script, SCRIPT_VERIFY_NONE, BaseSignatureChecker{}, slh_exec, err));
    BOOST_CHECK_EQUAL(slh_exec.m_validation_weight_left, 77);
}

BOOST_AUTO_TEST_CASE(csfs_validation_weight_exhaustion_and_boundary)
{
    CPQKey key;
    key.MakeNewKey(PQAlgorithm::ML_DSA_44);
    BOOST_REQUIRE(key.IsValid());
    const std::vector<unsigned char> msg{0x70, 0x71};
    const std::vector<unsigned char> sig = CreateCSFSSignature(key, msg);

    CScript repeat_script;
    repeat_script << key.GetPubKey() << OP_CHECKSIGFROMSTACK << OP_DROP << key.GetPubKey() << OP_CHECKSIGFROMSTACK;

    std::vector<std::vector<unsigned char>> repeat_stack{sig, msg, sig, msg};
    ScriptExecutionData exhausted;
    exhausted.m_validation_weight_left_init = true;
    exhausted.m_validation_weight_left = (2 * VALIDATION_WEIGHT_PER_MLDSA_SIGOP) - 1;
    ScriptError err{SCRIPT_ERR_UNKNOWN_ERROR};
    BOOST_CHECK(!EvalP2MRScript(repeat_stack, repeat_script, SCRIPT_VERIFY_NONE, BaseSignatureChecker{}, exhausted, err));
    BOOST_CHECK_EQUAL(err, SCRIPT_ERR_TAPSCRIPT_VALIDATION_WEIGHT);

    const std::vector<unsigned char> single_script_bytes = BuildP2MRCSFSScript(PQAlgorithm::ML_DSA_44, key.GetPubKey());
    const CScript single_script(single_script_bytes.begin(), single_script_bytes.end());
    std::vector<std::vector<unsigned char>> at_limit_stack{sig, msg};
    ScriptExecutionData at_limit;
    at_limit.m_validation_weight_left_init = true;
    at_limit.m_validation_weight_left = VALIDATION_WEIGHT_PER_MLDSA_SIGOP;
    err = SCRIPT_ERR_UNKNOWN_ERROR;
    BOOST_REQUIRE(EvalP2MRScript(at_limit_stack, single_script, SCRIPT_VERIFY_NONE, BaseSignatureChecker{}, at_limit, err));
    BOOST_CHECK_EQUAL(at_limit.m_validation_weight_left, 0);

    std::vector<std::vector<unsigned char>> over_limit_stack{sig, msg};
    ScriptExecutionData over_limit;
    over_limit.m_validation_weight_left_init = true;
    over_limit.m_validation_weight_left = VALIDATION_WEIGHT_PER_MLDSA_SIGOP - 1;
    err = SCRIPT_ERR_UNKNOWN_ERROR;
    BOOST_CHECK(!EvalP2MRScript(over_limit_stack, single_script, SCRIPT_VERIFY_NONE, BaseSignatureChecker{}, over_limit, err));
    BOOST_CHECK_EQUAL(err, SCRIPT_ERR_TAPSCRIPT_VALIDATION_WEIGHT);
}

BOOST_AUTO_TEST_CASE(csfs_standard_delegation_oracle_and_spender)
{
    CPQKey oracle_key;
    oracle_key.MakeNewKey(PQAlgorithm::SLH_DSA_128S);
    BOOST_REQUIRE(oracle_key.IsValid());
    CPQKey spender_key;
    spender_key.MakeNewKey(PQAlgorithm::ML_DSA_44);
    BOOST_REQUIRE(spender_key.IsValid());

    const std::vector<unsigned char> leaf_script = BuildP2MRDelegationScript(
        PQAlgorithm::SLH_DSA_128S, oracle_key.GetPubKey(),
        PQAlgorithm::ML_DSA_44, spender_key.GetPubKey());
    const uint256 merkle_root = ComputeP2MRMerkleRoot({ComputeP2MRLeafHash(P2MR_LEAF_VERSION, leaf_script)});
    P2MRSpendContext ctx{BuildP2MROutput(merkle_root)};

    const auto sighash = ComputeP2MRSighash(ctx, leaf_script);
    BOOST_REQUIRE(sighash.has_value());
    std::vector<unsigned char> sig_checksig;
    BOOST_REQUIRE(spender_key.Sign(*sighash, sig_checksig));

    const std::vector<unsigned char> msg{0x01, 0x02, 0x03};
    const std::vector<unsigned char> sig_csfs = CreateCSFSSignature(oracle_key, msg);

    CScriptWitness witness;
    witness.stack = {sig_checksig, sig_csfs, msg, leaf_script, {P2MR_LEAF_VERSION}};
    ScriptError err{SCRIPT_ERR_UNKNOWN_ERROR};
    BOOST_CHECK(VerifyP2MRSpend(ctx, witness, err));
    BOOST_CHECK_EQUAL(err, SCRIPT_ERR_OK);
}

BOOST_AUTO_TEST_CASE(csfs_delegation_invalid_oracle_signature_fails)
{
    CPQKey oracle_key;
    oracle_key.MakeNewKey(PQAlgorithm::SLH_DSA_128S);
    BOOST_REQUIRE(oracle_key.IsValid());
    CPQKey spender_key;
    spender_key.MakeNewKey(PQAlgorithm::ML_DSA_44);
    BOOST_REQUIRE(spender_key.IsValid());

    const std::vector<unsigned char> leaf_script = BuildP2MRDelegationScript(
        PQAlgorithm::SLH_DSA_128S, oracle_key.GetPubKey(),
        PQAlgorithm::ML_DSA_44, spender_key.GetPubKey());
    const uint256 merkle_root = ComputeP2MRMerkleRoot({ComputeP2MRLeafHash(P2MR_LEAF_VERSION, leaf_script)});
    P2MRSpendContext ctx{BuildP2MROutput(merkle_root)};

    const auto sighash = ComputeP2MRSighash(ctx, leaf_script);
    BOOST_REQUIRE(sighash.has_value());
    std::vector<unsigned char> sig_checksig;
    BOOST_REQUIRE(spender_key.Sign(*sighash, sig_checksig));

    const std::vector<unsigned char> msg{0x0A, 0x0B};
    std::vector<unsigned char> sig_csfs = CreateCSFSSignature(oracle_key, msg);
    sig_csfs[0] ^= 0x01;

    CScriptWitness witness;
    witness.stack = {sig_checksig, sig_csfs, msg, leaf_script, {P2MR_LEAF_VERSION}};
    ScriptError err{SCRIPT_ERR_UNKNOWN_ERROR};
    const unsigned int flags = P2MR_SCRIPT_FLAGS & ~SCRIPT_VERIFY_NULLFAIL;
    BOOST_CHECK(!VerifyP2MRSpendWithFlags(ctx, witness, flags, err));
    BOOST_CHECK_EQUAL(err, SCRIPT_ERR_VERIFY);
}

BOOST_AUTO_TEST_CASE(csfs_delegation_invalid_spender_signature_fails)
{
    CPQKey oracle_key;
    oracle_key.MakeNewKey(PQAlgorithm::SLH_DSA_128S);
    BOOST_REQUIRE(oracle_key.IsValid());
    CPQKey spender_key;
    spender_key.MakeNewKey(PQAlgorithm::ML_DSA_44);
    BOOST_REQUIRE(spender_key.IsValid());

    const std::vector<unsigned char> leaf_script = BuildP2MRDelegationScript(
        PQAlgorithm::SLH_DSA_128S, oracle_key.GetPubKey(),
        PQAlgorithm::ML_DSA_44, spender_key.GetPubKey());
    const uint256 merkle_root = ComputeP2MRMerkleRoot({ComputeP2MRLeafHash(P2MR_LEAF_VERSION, leaf_script)});
    P2MRSpendContext ctx{BuildP2MROutput(merkle_root)};

    const auto sighash = ComputeP2MRSighash(ctx, leaf_script);
    BOOST_REQUIRE(sighash.has_value());
    std::vector<unsigned char> sig_checksig;
    BOOST_REQUIRE(spender_key.Sign(*sighash, sig_checksig));
    sig_checksig[0] ^= 0x01;

    const std::vector<unsigned char> msg{0xFA, 0xFB};
    const std::vector<unsigned char> sig_csfs = CreateCSFSSignature(oracle_key, msg);

    CScriptWitness witness;
    witness.stack = {sig_checksig, sig_csfs, msg, leaf_script, {P2MR_LEAF_VERSION}};
    ScriptError err{SCRIPT_ERR_UNKNOWN_ERROR};
    const unsigned int flags = P2MR_SCRIPT_FLAGS & ~SCRIPT_VERIFY_NULLFAIL;
    BOOST_CHECK(!VerifyP2MRSpendWithFlags(ctx, witness, flags, err));
    BOOST_CHECK_EQUAL(err, SCRIPT_ERR_EVAL_FALSE);
}

BOOST_AUTO_TEST_CASE(csfs_delegation_leaf_size_expectations)
{
    CPQKey slh_oracle;
    slh_oracle.MakeNewKey(PQAlgorithm::SLH_DSA_128S);
    BOOST_REQUIRE(slh_oracle.IsValid());
    CPQKey ml_spender;
    ml_spender.MakeNewKey(PQAlgorithm::ML_DSA_44);
    BOOST_REQUIRE(ml_spender.IsValid());
    const std::vector<unsigned char> standard_leaf = BuildP2MRDelegationScript(
        PQAlgorithm::SLH_DSA_128S, slh_oracle.GetPubKey(),
        PQAlgorithm::ML_DSA_44, ml_spender.GetPubKey());
    BOOST_CHECK_LE(standard_leaf.size(), 1650U);

    CPQKey ml_oracle;
    ml_oracle.MakeNewKey(PQAlgorithm::ML_DSA_44);
    BOOST_REQUIRE(ml_oracle.IsValid());
    CPQKey ml_spender2;
    ml_spender2.MakeNewKey(PQAlgorithm::ML_DSA_44);
    BOOST_REQUIRE(ml_spender2.IsValid());
    const std::vector<unsigned char> two_ml_leaf = BuildP2MRDelegationScript(
        PQAlgorithm::ML_DSA_44, ml_oracle.GetPubKey(),
        PQAlgorithm::ML_DSA_44, ml_spender2.GetPubKey());
    BOOST_CHECK_GT(two_ml_leaf.size(), 1650U);
    BOOST_CHECK_LT(two_ml_leaf.size(), MAX_P2MR_SCRIPT_SIZE);

    const uint256 merkle_root = ComputeP2MRMerkleRoot({ComputeP2MRLeafHash(P2MR_LEAF_VERSION, two_ml_leaf)});
    P2MRSpendContext ctx{BuildP2MROutput(merkle_root)};

    const auto sighash = ComputeP2MRSighash(ctx, two_ml_leaf);
    BOOST_REQUIRE(sighash.has_value());
    std::vector<unsigned char> sig_checksig;
    BOOST_REQUIRE(ml_spender2.Sign(*sighash, sig_checksig));
    const std::vector<unsigned char> msg{0x33, 0x44};
    const std::vector<unsigned char> sig_csfs = CreateCSFSSignature(ml_oracle, msg);

    CScriptWitness witness;
    witness.stack = {sig_checksig, sig_csfs, msg, two_ml_leaf, {P2MR_LEAF_VERSION}};
    ScriptError err{SCRIPT_ERR_UNKNOWN_ERROR};
    BOOST_CHECK(VerifyP2MRSpend(ctx, witness, err));
    BOOST_CHECK_EQUAL(err, SCRIPT_ERR_OK);
}

BOOST_AUTO_TEST_CASE(consensus_rejects_non_p2mr_outputs_in_blocks)
{
    const auto main_params = CreateChainParams(*m_node.args, ChainType::MAIN);
    CTxOut non_p2mr_out;
    non_p2mr_out.nValue = 50 * COIN;
    non_p2mr_out.scriptPubKey = CScript{} << OP_TRUE;

    CBlock block = BuildSingleCoinbaseBlock({non_p2mr_out});
    BlockValidationState state;
    BOOST_CHECK(!CheckBlock(block, state, main_params->GetConsensus(), /*fCheckPOW=*/false, /*fCheckMerkleRoot=*/false));
    BOOST_CHECK_EQUAL(state.GetRejectReason(), "bad-txns-nonp2mr-output");
}

BOOST_AUTO_TEST_CASE(consensus_accepts_p2mr_outputs_in_blocks)
{
    const auto main_params = CreateChainParams(*m_node.args, ChainType::MAIN);
    const uint256 root = uint256::ONE;
    CTxOut p2mr_out;
    p2mr_out.nValue = 50 * COIN;
    p2mr_out.scriptPubKey = BuildP2MROutput(root);

    CBlock block = BuildSingleCoinbaseBlock({p2mr_out});
    BlockValidationState state;
    BOOST_CHECK(CheckBlock(block, state, main_params->GetConsensus(), /*fCheckPOW=*/false, /*fCheckMerkleRoot=*/false));
}

BOOST_AUTO_TEST_CASE(consensus_accepts_opreturn_and_p2mr_outputs_in_blocks)
{
    const auto main_params = CreateChainParams(*m_node.args, ChainType::MAIN);
    CTxOut p2mr_out;
    p2mr_out.nValue = 50 * COIN;
    p2mr_out.scriptPubKey = BuildP2MROutput(uint256::ONE);

    CTxOut op_return_out;
    op_return_out.nValue = 0;
    op_return_out.scriptPubKey = CScript{} << OP_RETURN << std::vector<unsigned char>{0x42, 0x54, 0x58};

    CBlock block = BuildSingleCoinbaseBlock({p2mr_out, op_return_out});
    BlockValidationState state;
    BOOST_CHECK(CheckBlock(block, state, main_params->GetConsensus(), /*fCheckPOW=*/false, /*fCheckMerkleRoot=*/false));
}

BOOST_AUTO_TEST_CASE(consensus_rejects_oversized_serialized_blocks)
{
    const auto main_params = CreateChainParams(*m_node.args, ChainType::MAIN);
    const auto& consensus = main_params->GetConsensus();

    CTxOut p2mr_out;
    p2mr_out.nValue = 50 * COIN;
    p2mr_out.scriptPubKey = BuildP2MROutput(uint256::ONE);

    CBlock block = BuildSingleCoinbaseBlock({p2mr_out});
    CMutableTransaction coinbase{*block.vtx.at(0)};

    const size_t block_size = ::GetSerializeSize(TX_WITH_WITNESS(block));
    BOOST_REQUIRE_LT(block_size, consensus.nMaxBlockSerializedSize + 1);
    const size_t witness_padding_size = consensus.nMaxBlockSerializedSize + 1 - block_size;
    coinbase.vin.at(0).scriptWitness.stack.emplace_back(witness_padding_size, 0x42);
    block.vtx.at(0) = MakeTransactionRef(std::move(coinbase));

    BlockValidationState state;
    BOOST_CHECK(!CheckBlock(block, state, consensus, /*fCheckPOW=*/false, /*fCheckMerkleRoot=*/false));
    BOOST_CHECK_EQUAL(state.GetRejectReason(), "bad-blk-length");
}

BOOST_AUTO_TEST_SUITE_END()
