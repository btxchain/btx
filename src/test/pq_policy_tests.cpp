// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <coins.h>
#include <hash.h>
#include <policy/policy.h>
#include <policy/settings.h>
#include <pqkey.h>
#include <script/interpreter.h>
#include <script/pqm.h>
#include <script/script.h>
#include <script/solver.h>
#include <test/util/setup_common.h>
#include <test/util/transaction_utils.h>
#include <util/rbf.h>
#include <validation.h>

#include <boost/test/unit_test.hpp>

#include <array>
#include <cassert>
#include <optional>
#include <string>
#include <vector>

namespace {

constexpr size_t RESERVED_FALCON512_PUBKEY_SIZE = 897;

std::vector<unsigned char> ToBytes(const uint256& hash)
{
    return std::vector<unsigned char>(hash.begin(), hash.end());
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

uint256 ComputeCSFSHash(Span<const unsigned char> msg)
{
    HashWriter hasher = HASHER_CSFS;
    hasher.write(MakeByteSpan(msg));
    return hasher.GetSHA256();
}

std::vector<unsigned char> SignCSFSMessage(const CPQKey& key, Span<const unsigned char> msg)
{
    std::vector<unsigned char> sig;
    const bool ok = key.Sign(ComputeCSFSHash(msg), sig);
    assert(ok);
    return sig;
}

CScript BuildP2MROutput(const uint256& merkle_root)
{
    CScript script;
    script << OP_2 << ToBytes(merkle_root);
    return script;
}

std::vector<unsigned char> BuildRawP2MRMultisigLeafScript(
    uint8_t threshold,
    const std::vector<std::pair<PQAlgorithm, std::vector<unsigned char>>>& pubkeys)
{
    CScript script;
    for (size_t i = 0; i < pubkeys.size(); ++i) {
        const auto& [algo, pubkey] = pubkeys[i];
        script << pubkey;
        if (i == 0) {
            script << (algo == PQAlgorithm::ML_DSA_44 ? OP_CHECKSIG_MLDSA : OP_CHECKSIG_SLHDSA);
        } else {
            script << (algo == PQAlgorithm::ML_DSA_44 ? OP_CHECKSIGADD_MLDSA : OP_CHECKSIGADD_SLHDSA);
        }
    }
    script << static_cast<int64_t>(threshold) << OP_NUMEQUAL;
    return std::vector<unsigned char>(script.begin(), script.end());
}

std::vector<unsigned char> BuildReservedFalconLeafScript(opcodetype opcode, unsigned char fill_byte)
{
    CScript script;
    script << std::vector<unsigned char>(RESERVED_FALCON512_PUBKEY_SIZE, fill_byte) << opcode;
    return std::vector<unsigned char>(script.begin(), script.end());
}

std::optional<CScriptWitness> BuildSignedSingleLeafP2MRWitness(
    CMutableTransaction& spend_tx,
    const CTxOut& prevout,
    const CPQKey& key,
    Span<const unsigned char> leaf_script)
{
    PrecomputedTransactionData txdata;
    txdata.Init(spend_tx, {prevout}, /*force=*/true);

    ScriptExecutionData execdata;
    execdata.m_annex_present = false;
    execdata.m_annex_init = true;
    execdata.m_tapleaf_hash = ComputeP2MRLeafHash(P2MR_LEAF_VERSION, leaf_script);
    execdata.m_tapleaf_hash_init = true;
    execdata.m_codeseparator_pos = 0xFFFFFFFFU;
    execdata.m_codeseparator_pos_init = true;

    uint256 sighash;
    if (!SignatureHashSchnorr(
            sighash,
            execdata,
            spend_tx,
            /*in_pos=*/0,
            SIGHASH_DEFAULT,
            SigVersion::P2MR,
            txdata,
            MissingDataBehavior::ASSERT_FAIL)) {
        return std::nullopt;
    }

    std::vector<unsigned char> signature;
    if (!key.Sign(sighash, signature)) {
        return std::nullopt;
    }

    CScriptWitness witness;
    witness.stack = {
        signature,
        std::vector<unsigned char>(leaf_script.begin(), leaf_script.end()),
        {P2MR_LEAF_VERSION},
    };
    return witness;
}

std::optional<CScriptWitness> BuildSignedMultisigLeafP2MRWitness(
    CMutableTransaction& spend_tx,
    const CTxOut& prevout,
    Span<const CPQKey> keys_in_script_order,
    size_t threshold,
    Span<const unsigned char> leaf_script)
{
    if (keys_in_script_order.empty()) return std::nullopt;
    if (threshold < 1 || threshold > keys_in_script_order.size()) return std::nullopt;

    PrecomputedTransactionData txdata;
    txdata.Init(spend_tx, {prevout}, /*force=*/true);

    ScriptExecutionData execdata;
    execdata.m_annex_present = false;
    execdata.m_annex_init = true;
    execdata.m_tapleaf_hash = ComputeP2MRLeafHash(P2MR_LEAF_VERSION, leaf_script);
    execdata.m_tapleaf_hash_init = true;
    execdata.m_codeseparator_pos = 0xFFFFFFFFU;
    execdata.m_codeseparator_pos_init = true;

    uint256 sighash;
    if (!SignatureHashSchnorr(
            sighash,
            execdata,
            spend_tx,
            /*in_pos=*/0,
            SIGHASH_DEFAULT,
            SigVersion::P2MR,
            txdata,
            MissingDataBehavior::ASSERT_FAIL)) {
        return std::nullopt;
    }

    std::vector<std::vector<unsigned char>> sigs(keys_in_script_order.size());
    for (size_t i = 0; i < threshold; ++i) {
        if (!keys_in_script_order[i].Sign(sighash, sigs[i])) return std::nullopt;
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

} // namespace

BOOST_FIXTURE_TEST_SUITE(pq_policy_tests, TestChain100Setup)

BOOST_AUTO_TEST_CASE(p2mr_output_is_standard)
{
    TxoutType which{};
    const CScript spk = BuildP2MROutput(uint256::ONE);
    BOOST_CHECK(IsStandard(spk, std::optional<unsigned>{MAX_OP_RETURN_RELAY}, which));
    BOOST_CHECK_EQUAL(which, TxoutType::WITNESS_V2_P2MR);
}

BOOST_AUTO_TEST_CASE(legacy_p2pkh_output_is_nonstandard)
{
    TxoutType which{};
    const CScript spk = GetScriptForDestination(PKHash(coinbaseKey.GetPubKey()));
    BOOST_CHECK(!IsStandard(spk, std::optional<unsigned>{MAX_OP_RETURN_RELAY}, which));
}

BOOST_AUTO_TEST_CASE(p2wpkh_output_is_nonstandard)
{
    TxoutType which{};
    const CScript spk = GetScriptForDestination(WitnessV0KeyHash(coinbaseKey.GetPubKey()));
    BOOST_CHECK(!IsStandard(spk, std::optional<unsigned>{MAX_OP_RETURN_RELAY}, which));
}

BOOST_AUTO_TEST_CASE(taproot_output_is_nonstandard)
{
    CKey key;
    key.MakeNewKey(/*fCompressed=*/true);

    TxoutType which{};
    const CScript spk = GetScriptForDestination(WitnessV1Taproot{XOnlyPubKey{key.GetPubKey()}});
    BOOST_CHECK(!IsStandard(spk, std::optional<unsigned>{MAX_OP_RETURN_RELAY}, which));
}

BOOST_AUTO_TEST_CASE(p2mr_witness_is_standard)
{
    CPQKey spend_key;
    spend_key.MakeNewKey(PQAlgorithm::ML_DSA_44);
    BOOST_REQUIRE(spend_key.IsValid());

    const std::vector<unsigned char> leaf_script = BuildP2MRScript(PQAlgorithm::ML_DSA_44, spend_key.GetPubKey());
    const uint256 leaf_hash = ComputeP2MRLeafHash(P2MR_LEAF_VERSION, leaf_script);
    const uint256 merkle_root = ComputeP2MRMerkleRoot({leaf_hash});

    const CMutableTransaction tx_credit = BuildCreditingTransaction(BuildP2MROutput(merkle_root), /*nValue=*/50'000);
    CMutableTransaction tx_spend = BuildSpendingTransaction(CScript{}, CScriptWitness{}, CTransaction{tx_credit});

    const auto witness = BuildSignedSingleLeafP2MRWitness(tx_spend, tx_credit.vout.at(0), spend_key, leaf_script);
    BOOST_REQUIRE(witness.has_value());
    tx_spend.vin.at(0).scriptWitness = *witness;

    CCoinsView coins_view;
    CCoinsViewCache coins_cache(&coins_view);
    AddCoins(coins_cache, CTransaction{tx_credit}, /*nHeight=*/0);

    std::string reason;
    BOOST_CHECK(IsWitnessStandard(CTransaction{tx_spend}, coins_cache, "", reason));
}

BOOST_AUTO_TEST_CASE(p2mr_annex_is_nonstandard_by_policy)
{
    CPQKey spend_key;
    spend_key.MakeNewKey(PQAlgorithm::ML_DSA_44);
    BOOST_REQUIRE(spend_key.IsValid());

    const std::vector<unsigned char> leaf_script = BuildP2MRScript(PQAlgorithm::ML_DSA_44, spend_key.GetPubKey());
    const uint256 leaf_hash = ComputeP2MRLeafHash(P2MR_LEAF_VERSION, leaf_script);
    const uint256 merkle_root = ComputeP2MRMerkleRoot({leaf_hash});

    const CMutableTransaction tx_credit = BuildCreditingTransaction(BuildP2MROutput(merkle_root), /*nValue=*/50'000);
    CMutableTransaction tx_spend = BuildSpendingTransaction(CScript{}, CScriptWitness{}, CTransaction{tx_credit});

    const auto witness = BuildSignedSingleLeafP2MRWitness(tx_spend, tx_credit.vout.at(0), spend_key, leaf_script);
    BOOST_REQUIRE(witness.has_value());
    tx_spend.vin.at(0).scriptWitness = *witness;
    tx_spend.vin.at(0).scriptWitness.stack.push_back({ANNEX_TAG, 0x42});

    CCoinsView coins_view;
    CCoinsViewCache coins_cache(&coins_view);
    AddCoins(coins_cache, CTransaction{tx_credit}, /*nHeight=*/0);

    std::string reason;
    BOOST_CHECK(!IsWitnessStandard(CTransaction{tx_spend}, coins_cache, "", reason));
    BOOST_CHECK_EQUAL(reason, "p2mr-annex");
}

BOOST_AUTO_TEST_CASE(p2mr_multisig_witness_is_standard)
{
    CPQKey key1;
    key1.MakeNewKey(PQAlgorithm::ML_DSA_44);
    BOOST_REQUIRE(key1.IsValid());
    CPQKey key2;
    key2.MakeNewKey(PQAlgorithm::ML_DSA_44);
    BOOST_REQUIRE(key2.IsValid());
    CPQKey key3;
    key3.MakeNewKey(PQAlgorithm::SLH_DSA_128S);
    BOOST_REQUIRE(key3.IsValid());

    const std::vector<unsigned char> leaf_script = BuildP2MRMultisigScript(
        /*threshold=*/2,
        {
            {PQAlgorithm::ML_DSA_44, key1.GetPubKey()},
            {PQAlgorithm::ML_DSA_44, key2.GetPubKey()},
            {PQAlgorithm::SLH_DSA_128S, key3.GetPubKey()},
        });
    BOOST_REQUIRE(!leaf_script.empty());
    BOOST_CHECK_GT(leaf_script.size(), g_script_size_policy_limit);

    const uint256 leaf_hash = ComputeP2MRLeafHash(P2MR_LEAF_VERSION, leaf_script);
    const uint256 merkle_root = ComputeP2MRMerkleRoot({leaf_hash});

    const CMutableTransaction tx_credit = BuildCreditingTransaction(BuildP2MROutput(merkle_root), /*nValue=*/50'000);
    CMutableTransaction tx_spend = BuildSpendingTransaction(CScript{}, CScriptWitness{}, CTransaction{tx_credit});

    const std::vector<CPQKey> signer_keys{key1, key2, key3};
    const auto witness = BuildSignedMultisigLeafP2MRWitness(tx_spend, tx_credit.vout.at(0), signer_keys, /*threshold=*/2, leaf_script);
    BOOST_REQUIRE(witness.has_value());
    tx_spend.vin.at(0).scriptWitness = *witness;

    CCoinsView coins_view;
    CCoinsViewCache coins_cache(&coins_view);
    AddCoins(coins_cache, CTransaction{tx_credit}, /*nHeight=*/0);

    std::string reason;
    BOOST_CHECK(IsWitnessStandard(CTransaction{tx_spend}, coins_cache, "", reason));
}

BOOST_AUTO_TEST_CASE(p2mr_cltv_multisig_witness_is_standard)
{
    CPQKey key1;
    key1.MakeNewKey(PQAlgorithm::ML_DSA_44);
    BOOST_REQUIRE(key1.IsValid());
    CPQKey key2;
    key2.MakeNewKey(PQAlgorithm::ML_DSA_44);
    BOOST_REQUIRE(key2.IsValid());
    CPQKey key3;
    key3.MakeNewKey(PQAlgorithm::SLH_DSA_128S);
    BOOST_REQUIRE(key3.IsValid());

    const std::vector<unsigned char> leaf_script = BuildP2MRCLTVMultisigScript(
        /*locktime=*/700,
        /*threshold=*/2,
        {
            {PQAlgorithm::ML_DSA_44, key1.GetPubKey()},
            {PQAlgorithm::ML_DSA_44, key2.GetPubKey()},
            {PQAlgorithm::SLH_DSA_128S, key3.GetPubKey()},
        });
    BOOST_REQUIRE(!leaf_script.empty());
    BOOST_CHECK_GT(leaf_script.size(), g_script_size_policy_limit);

    const uint256 leaf_hash = ComputeP2MRLeafHash(P2MR_LEAF_VERSION, leaf_script);
    const uint256 merkle_root = ComputeP2MRMerkleRoot({leaf_hash});

    const CMutableTransaction tx_credit = BuildCreditingTransaction(BuildP2MROutput(merkle_root), /*nValue=*/50'000);
    CMutableTransaction tx_spend = BuildSpendingTransaction(CScript{}, CScriptWitness{}, CTransaction{tx_credit});

    const std::vector<CPQKey> signer_keys{key1, key2, key3};
    const auto witness = BuildSignedMultisigLeafP2MRWitness(tx_spend, tx_credit.vout.at(0), signer_keys, /*threshold=*/2, leaf_script);
    BOOST_REQUIRE(witness.has_value());
    tx_spend.vin.at(0).scriptWitness = *witness;

    CCoinsView coins_view;
    CCoinsViewCache coins_cache(&coins_view);
    AddCoins(coins_cache, CTransaction{tx_credit}, /*nHeight=*/0);

    std::string reason;
    BOOST_CHECK(IsWitnessStandard(CTransaction{tx_spend}, coins_cache, "", reason));
}

BOOST_AUTO_TEST_CASE(p2mr_csv_multisig_witness_is_standard)
{
    CPQKey key1;
    key1.MakeNewKey(PQAlgorithm::ML_DSA_44);
    BOOST_REQUIRE(key1.IsValid());
    CPQKey key2;
    key2.MakeNewKey(PQAlgorithm::ML_DSA_44);
    BOOST_REQUIRE(key2.IsValid());
    CPQKey key3;
    key3.MakeNewKey(PQAlgorithm::SLH_DSA_128S);
    BOOST_REQUIRE(key3.IsValid());

    const std::vector<unsigned char> leaf_script = BuildP2MRCSVMultisigScript(
        /*sequence=*/144,
        /*threshold=*/2,
        {
            {PQAlgorithm::ML_DSA_44, key1.GetPubKey()},
            {PQAlgorithm::ML_DSA_44, key2.GetPubKey()},
            {PQAlgorithm::SLH_DSA_128S, key3.GetPubKey()},
        });
    BOOST_REQUIRE(!leaf_script.empty());
    BOOST_CHECK_GT(leaf_script.size(), g_script_size_policy_limit);

    const uint256 leaf_hash = ComputeP2MRLeafHash(P2MR_LEAF_VERSION, leaf_script);
    const uint256 merkle_root = ComputeP2MRMerkleRoot({leaf_hash});

    const CMutableTransaction tx_credit = BuildCreditingTransaction(BuildP2MROutput(merkle_root), /*nValue=*/50'000);
    CMutableTransaction tx_spend = BuildSpendingTransaction(CScript{}, CScriptWitness{}, CTransaction{tx_credit});

    const std::vector<CPQKey> signer_keys{key1, key2, key3};
    const auto witness = BuildSignedMultisigLeafP2MRWitness(tx_spend, tx_credit.vout.at(0), signer_keys, /*threshold=*/2, leaf_script);
    BOOST_REQUIRE(witness.has_value());
    tx_spend.vin.at(0).scriptWitness = *witness;

    CCoinsView coins_view;
    CCoinsViewCache coins_cache(&coins_view);
    AddCoins(coins_cache, CTransaction{tx_credit}, /*nHeight=*/0);

    std::string reason;
    BOOST_CHECK(IsWitnessStandard(CTransaction{tx_spend}, coins_cache, "", reason));
}

BOOST_AUTO_TEST_CASE(p2mr_ctv_multisig_witness_is_standard)
{
    CPQKey key1;
    key1.MakeNewKey(PQAlgorithm::ML_DSA_44);
    BOOST_REQUIRE(key1.IsValid());
    CPQKey key2;
    key2.MakeNewKey(PQAlgorithm::ML_DSA_44);
    BOOST_REQUIRE(key2.IsValid());
    CPQKey key3;
    key3.MakeNewKey(PQAlgorithm::SLH_DSA_128S);
    BOOST_REQUIRE(key3.IsValid());

    const uint256 ctv_hash = Hash(std::vector<unsigned char>{0x51, 0x52, 0x53});
    const std::vector<unsigned char> leaf_script = BuildP2MRMultisigCTVScript(
        ctv_hash,
        /*threshold=*/2,
        {
            {PQAlgorithm::ML_DSA_44, key1.GetPubKey()},
            {PQAlgorithm::ML_DSA_44, key2.GetPubKey()},
            {PQAlgorithm::SLH_DSA_128S, key3.GetPubKey()},
        });
    BOOST_REQUIRE(!leaf_script.empty());
    BOOST_CHECK_GT(leaf_script.size(), g_script_size_policy_limit);

    const uint256 leaf_hash = ComputeP2MRLeafHash(P2MR_LEAF_VERSION, leaf_script);
    const uint256 merkle_root = ComputeP2MRMerkleRoot({leaf_hash});

    const CMutableTransaction tx_credit = BuildCreditingTransaction(BuildP2MROutput(merkle_root), /*nValue=*/50'000);
    CMutableTransaction tx_spend = BuildSpendingTransaction(CScript{}, CScriptWitness{}, CTransaction{tx_credit});

    const std::vector<CPQKey> signer_keys{key1, key2, key3};
    const auto witness = BuildSignedMultisigLeafP2MRWitness(tx_spend, tx_credit.vout.at(0), signer_keys, /*threshold=*/2, leaf_script);
    BOOST_REQUIRE(witness.has_value());
    tx_spend.vin.at(0).scriptWitness = *witness;

    CCoinsView coins_view;
    CCoinsViewCache coins_cache(&coins_view);
    AddCoins(coins_cache, CTransaction{tx_credit}, /*nHeight=*/0);

    std::string reason;
    BOOST_CHECK(IsWitnessStandard(CTransaction{tx_spend}, coins_cache, "", reason));
}

BOOST_AUTO_TEST_CASE(p2mr_multisig_with_too_many_sigs_rejected_by_policy)
{
    CPQKey key1;
    key1.MakeNewKey(PQAlgorithm::ML_DSA_44);
    BOOST_REQUIRE(key1.IsValid());
    CPQKey key2;
    key2.MakeNewKey(PQAlgorithm::ML_DSA_44);
    BOOST_REQUIRE(key2.IsValid());
    CPQKey key3;
    key3.MakeNewKey(PQAlgorithm::SLH_DSA_128S);
    BOOST_REQUIRE(key3.IsValid());

    const std::vector<unsigned char> leaf_script = BuildP2MRMultisigScript(
        /*threshold=*/2,
        {
            {PQAlgorithm::ML_DSA_44, key1.GetPubKey()},
            {PQAlgorithm::ML_DSA_44, key2.GetPubKey()},
            {PQAlgorithm::SLH_DSA_128S, key3.GetPubKey()},
        });
    BOOST_REQUIRE(!leaf_script.empty());

    const uint256 leaf_hash = ComputeP2MRLeafHash(P2MR_LEAF_VERSION, leaf_script);
    const uint256 merkle_root = ComputeP2MRMerkleRoot({leaf_hash});

    const CMutableTransaction tx_credit = BuildCreditingTransaction(BuildP2MROutput(merkle_root), /*nValue=*/50'000);
    CMutableTransaction tx_spend = BuildSpendingTransaction(CScript{}, CScriptWitness{}, CTransaction{tx_credit});

    const std::vector<CPQKey> signer_keys{key1, key2, key3};
    const auto witness = BuildSignedMultisigLeafP2MRWitness(tx_spend, tx_credit.vout.at(0), signer_keys, /*threshold=*/3, leaf_script);
    BOOST_REQUIRE(witness.has_value());
    tx_spend.vin.at(0).scriptWitness = *witness;

    CCoinsView coins_view;
    CCoinsViewCache coins_cache(&coins_view);
    AddCoins(coins_cache, CTransaction{tx_credit}, /*nHeight=*/0);

    std::string reason;
    BOOST_CHECK(!IsWitnessStandard(CTransaction{tx_spend}, coins_cache, "", reason));
    BOOST_CHECK_EQUAL(reason, "p2mr-multisig-threshold");
}

BOOST_AUTO_TEST_CASE(p2mr_multisig_duplicate_pubkeys_rejected_by_policy)
{
    CPQKey key1;
    key1.MakeNewKey(PQAlgorithm::ML_DSA_44);
    BOOST_REQUIRE(key1.IsValid());
    CPQKey key2;
    key2.MakeNewKey(PQAlgorithm::SLH_DSA_128S);
    BOOST_REQUIRE(key2.IsValid());

    const std::vector<unsigned char> leaf_script = BuildRawP2MRMultisigLeafScript(
        /*threshold=*/2,
        {
            {PQAlgorithm::ML_DSA_44, key1.GetPubKey()},
            {PQAlgorithm::ML_DSA_44, key1.GetPubKey()},
            {PQAlgorithm::SLH_DSA_128S, key2.GetPubKey()},
        });
    BOOST_REQUIRE(!leaf_script.empty());

    const uint256 leaf_hash = ComputeP2MRLeafHash(P2MR_LEAF_VERSION, leaf_script);
    const uint256 merkle_root = ComputeP2MRMerkleRoot({leaf_hash});

    const CMutableTransaction tx_credit = BuildCreditingTransaction(BuildP2MROutput(merkle_root), /*nValue=*/50'000);
    CMutableTransaction tx_spend = BuildSpendingTransaction(CScript{}, CScriptWitness{}, CTransaction{tx_credit});

    const std::vector<CPQKey> signer_keys{key1, key1, key2};
    const auto witness = BuildSignedMultisigLeafP2MRWitness(tx_spend, tx_credit.vout.at(0), signer_keys, /*threshold=*/2, leaf_script);
    BOOST_REQUIRE(witness.has_value());
    tx_spend.vin.at(0).scriptWitness = *witness;

    CCoinsView coins_view;
    CCoinsViewCache coins_cache(&coins_view);
    AddCoins(coins_cache, CTransaction{tx_credit}, /*nHeight=*/0);

    std::string reason;
    BOOST_CHECK(!IsWitnessStandard(CTransaction{tx_spend}, coins_cache, "", reason));
    BOOST_CHECK_EQUAL(reason, "p2mr-leaf-script");
}

BOOST_AUTO_TEST_CASE(p2mr_reserved_falcon_leafs_rejected_by_policy)
{
    const std::array<std::vector<unsigned char>, 2> reserved_leafs{
        BuildReservedFalconLeafScript(OP_CHECKSIG_FALCON, 0x11),
        BuildReservedFalconLeafScript(OP_CHECKSIGFROMSTACK_FALCON, 0x22),
    };

    for (const auto& leaf_script : reserved_leafs) {
        const uint256 leaf_hash = ComputeP2MRLeafHash(P2MR_LEAF_VERSION, leaf_script);
        const uint256 merkle_root = ComputeP2MRMerkleRoot({leaf_hash});

        const CMutableTransaction tx_credit = BuildCreditingTransaction(BuildP2MROutput(merkle_root), /*nValue=*/50'000);
        CMutableTransaction tx_spend = BuildSpendingTransaction(CScript{}, CScriptWitness{}, CTransaction{tx_credit});
        tx_spend.vin.at(0).scriptWitness.stack = {leaf_script, {P2MR_LEAF_VERSION}};

        CCoinsView coins_view;
        CCoinsViewCache coins_cache(&coins_view);
        AddCoins(coins_cache, CTransaction{tx_credit}, /*nHeight=*/0);

        std::string reason;
        BOOST_CHECK(!IsWitnessStandard(CTransaction{tx_spend}, coins_cache, "", reason));
        BOOST_CHECK_EQUAL(reason, "p2mr-leaf-script");
    }
}

BOOST_AUTO_TEST_CASE(p2mr_ctv_only_witness_is_standard)
{
    const std::vector<unsigned char> leaf_script = BuildCTVOnlyLeafScript(uint256::ONE);
    const uint256 leaf_hash = ComputeP2MRLeafHash(P2MR_LEAF_VERSION, leaf_script);
    const uint256 merkle_root = ComputeP2MRMerkleRoot({leaf_hash});

    const CMutableTransaction tx_credit = BuildCreditingTransaction(BuildP2MROutput(merkle_root), /*nValue=*/50'000);
    CMutableTransaction tx_spend = BuildSpendingTransaction(CScript{}, CScriptWitness{}, CTransaction{tx_credit});

    tx_spend.vin.at(0).scriptWitness.stack = {leaf_script, {P2MR_LEAF_VERSION}};

    CCoinsView coins_view;
    CCoinsViewCache coins_cache(&coins_view);
    AddCoins(coins_cache, CTransaction{tx_credit}, /*nHeight=*/0);

    std::string reason;
    BOOST_CHECK(IsWitnessStandard(CTransaction{tx_spend}, coins_cache, "", reason));
}

BOOST_AUTO_TEST_CASE(p2mr_ctv_checksig_mldsa_witness_is_standard)
{
    CPQKey spend_key;
    spend_key.MakeNewKey(PQAlgorithm::ML_DSA_44);
    BOOST_REQUIRE(spend_key.IsValid());

    const std::vector<unsigned char> leaf_script = BuildCTVChecksigLeafScript(uint256::ONE, PQAlgorithm::ML_DSA_44, spend_key.GetPubKey());
    const uint256 leaf_hash = ComputeP2MRLeafHash(P2MR_LEAF_VERSION, leaf_script);
    const uint256 merkle_root = ComputeP2MRMerkleRoot({leaf_hash});

    const CMutableTransaction tx_credit = BuildCreditingTransaction(BuildP2MROutput(merkle_root), /*nValue=*/50'000);
    CMutableTransaction tx_spend = BuildSpendingTransaction(CScript{}, CScriptWitness{}, CTransaction{tx_credit});

    const auto witness = BuildSignedSingleLeafP2MRWitness(tx_spend, tx_credit.vout.at(0), spend_key, leaf_script);
    BOOST_REQUIRE(witness.has_value());
    tx_spend.vin.at(0).scriptWitness = *witness;

    CCoinsView coins_view;
    CCoinsViewCache coins_cache(&coins_view);
    AddCoins(coins_cache, CTransaction{tx_credit}, /*nHeight=*/0);

    std::string reason;
    BOOST_CHECK(IsWitnessStandard(CTransaction{tx_spend}, coins_cache, "", reason));
}

BOOST_AUTO_TEST_CASE(p2mr_ctv_checksig_slhdsa_witness_is_standard)
{
    CPQKey spend_key;
    spend_key.MakeNewKey(PQAlgorithm::SLH_DSA_128S);
    BOOST_REQUIRE(spend_key.IsValid());

    const std::vector<unsigned char> leaf_script = BuildCTVChecksigLeafScript(uint256::ONE, PQAlgorithm::SLH_DSA_128S, spend_key.GetPubKey());
    const uint256 leaf_hash = ComputeP2MRLeafHash(P2MR_LEAF_VERSION, leaf_script);
    const uint256 merkle_root = ComputeP2MRMerkleRoot({leaf_hash});

    const CMutableTransaction tx_credit = BuildCreditingTransaction(BuildP2MROutput(merkle_root), /*nValue=*/50'000);
    CMutableTransaction tx_spend = BuildSpendingTransaction(CScript{}, CScriptWitness{}, CTransaction{tx_credit});

    const auto witness = BuildSignedSingleLeafP2MRWitness(tx_spend, tx_credit.vout.at(0), spend_key, leaf_script);
    BOOST_REQUIRE(witness.has_value());
    tx_spend.vin.at(0).scriptWitness = *witness;

    CCoinsView coins_view;
    CCoinsViewCache coins_cache(&coins_view);
    AddCoins(coins_cache, CTransaction{tx_credit}, /*nHeight=*/0);

    std::string reason;
    BOOST_CHECK(IsWitnessStandard(CTransaction{tx_spend}, coins_cache, "", reason));
}

BOOST_AUTO_TEST_CASE(p2mr_csfs_only_witness_is_standard)
{
    CPQKey oracle_key;
    oracle_key.MakeNewKey(PQAlgorithm::ML_DSA_44);
    BOOST_REQUIRE(oracle_key.IsValid());

    const std::vector<unsigned char> leaf_script = BuildP2MRCSFSScript(PQAlgorithm::ML_DSA_44, oracle_key.GetPubKey());
    const uint256 leaf_hash = ComputeP2MRLeafHash(P2MR_LEAF_VERSION, leaf_script);
    const uint256 merkle_root = ComputeP2MRMerkleRoot({leaf_hash});

    const CMutableTransaction tx_credit = BuildCreditingTransaction(BuildP2MROutput(merkle_root), /*nValue=*/50'000);
    CMutableTransaction tx_spend = BuildSpendingTransaction(CScript{}, CScriptWitness{}, CTransaction{tx_credit});

    const std::vector<unsigned char> msg{0x01, 0x02, 0x03};
    const std::vector<unsigned char> sig_csfs = SignCSFSMessage(oracle_key, msg);
    tx_spend.vin.at(0).scriptWitness.stack = {sig_csfs, msg, leaf_script, {P2MR_LEAF_VERSION}};

    CCoinsView coins_view;
    CCoinsViewCache coins_cache(&coins_view);
    AddCoins(coins_cache, CTransaction{tx_credit}, /*nHeight=*/0);

    std::string reason;
    BOOST_CHECK(IsWitnessStandard(CTransaction{tx_spend}, coins_cache, "", reason));
}

BOOST_AUTO_TEST_CASE(p2mr_delegation_witness_is_standard)
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
    const uint256 leaf_hash = ComputeP2MRLeafHash(P2MR_LEAF_VERSION, leaf_script);
    const uint256 merkle_root = ComputeP2MRMerkleRoot({leaf_hash});

    const CMutableTransaction tx_credit = BuildCreditingTransaction(BuildP2MROutput(merkle_root), /*nValue=*/50'000);
    CMutableTransaction tx_spend = BuildSpendingTransaction(CScript{}, CScriptWitness{}, CTransaction{tx_credit});

    const auto witness = BuildSignedSingleLeafP2MRWitness(tx_spend, tx_credit.vout.at(0), spender_key, leaf_script);
    BOOST_REQUIRE(witness.has_value());
    tx_spend.vin.at(0).scriptWitness = *witness;

    const std::vector<unsigned char> msg{0x04, 0x05};
    tx_spend.vin.at(0).scriptWitness.stack.insert(tx_spend.vin.at(0).scriptWitness.stack.begin() + 1, SignCSFSMessage(oracle_key, msg));
    tx_spend.vin.at(0).scriptWitness.stack.insert(tx_spend.vin.at(0).scriptWitness.stack.begin() + 2, msg);
    BOOST_REQUIRE_EQUAL(tx_spend.vin.at(0).scriptWitness.stack.size(), 5U);

    CCoinsView coins_view;
    CCoinsViewCache coins_cache(&coins_view);
    AddCoins(coins_cache, CTransaction{tx_credit}, /*nHeight=*/0);

    std::string reason;
    BOOST_CHECK(IsWitnessStandard(CTransaction{tx_spend}, coins_cache, "", reason));
}

BOOST_AUTO_TEST_CASE(p2mr_backup_witness_is_standard)
{
    CPQKey spend_key;
    spend_key.MakeNewKey(PQAlgorithm::SLH_DSA_128S);
    BOOST_REQUIRE(spend_key.IsValid());

    const std::vector<unsigned char> leaf_script = BuildP2MRScript(PQAlgorithm::SLH_DSA_128S, spend_key.GetPubKey());
    const uint256 leaf_hash = ComputeP2MRLeafHash(P2MR_LEAF_VERSION, leaf_script);
    const uint256 merkle_root = ComputeP2MRMerkleRoot({leaf_hash});

    const CMutableTransaction tx_credit = BuildCreditingTransaction(BuildP2MROutput(merkle_root), /*nValue=*/50'000);
    CMutableTransaction tx_spend = BuildSpendingTransaction(CScript{}, CScriptWitness{}, CTransaction{tx_credit});

    const auto witness = BuildSignedSingleLeafP2MRWitness(tx_spend, tx_credit.vout.at(0), spend_key, leaf_script);
    BOOST_REQUIRE(witness.has_value());
    tx_spend.vin.at(0).scriptWitness = *witness;

    CCoinsView coins_view;
    CCoinsViewCache coins_cache(&coins_view);
    AddCoins(coins_cache, CTransaction{tx_credit}, /*nHeight=*/0);

    std::string reason;
    BOOST_CHECK(IsWitnessStandard(CTransaction{tx_spend}, coins_cache, "", reason));
}

BOOST_AUTO_TEST_CASE(p2mr_witness_rejects_bad_stack_size)
{
    CPQKey spend_key;
    spend_key.MakeNewKey(PQAlgorithm::ML_DSA_44);
    BOOST_REQUIRE(spend_key.IsValid());

    const std::vector<unsigned char> leaf_script = BuildP2MRScript(PQAlgorithm::ML_DSA_44, spend_key.GetPubKey());
    const uint256 leaf_hash = ComputeP2MRLeafHash(P2MR_LEAF_VERSION, leaf_script);
    const uint256 merkle_root = ComputeP2MRMerkleRoot({leaf_hash});

    const CMutableTransaction tx_credit = BuildCreditingTransaction(BuildP2MROutput(merkle_root), /*nValue=*/50'000);
    CMutableTransaction tx_spend = BuildSpendingTransaction(CScript{}, CScriptWitness{}, CTransaction{tx_credit});

    const auto witness = BuildSignedSingleLeafP2MRWitness(tx_spend, tx_credit.vout.at(0), spend_key, leaf_script);
    BOOST_REQUIRE(witness.has_value());
    tx_spend.vin.at(0).scriptWitness = *witness;
    tx_spend.vin.at(0).scriptWitness.stack.insert(tx_spend.vin.at(0).scriptWitness.stack.begin(), std::vector<unsigned char>{0x01});

    CCoinsView coins_view;
    CCoinsViewCache coins_cache(&coins_view);
    AddCoins(coins_cache, CTransaction{tx_credit}, /*nHeight=*/0);

    std::string reason;
    BOOST_CHECK(!IsWitnessStandard(CTransaction{tx_spend}, coins_cache, "", reason));
    BOOST_CHECK_EQUAL(reason, "p2mr-stack-size");
}

BOOST_AUTO_TEST_CASE(p2mr_witness_rejects_bad_control_size)
{
    CPQKey spend_key;
    spend_key.MakeNewKey(PQAlgorithm::ML_DSA_44);
    BOOST_REQUIRE(spend_key.IsValid());

    const std::vector<unsigned char> leaf_script = BuildP2MRScript(PQAlgorithm::ML_DSA_44, spend_key.GetPubKey());
    const uint256 leaf_hash = ComputeP2MRLeafHash(P2MR_LEAF_VERSION, leaf_script);
    const uint256 merkle_root = ComputeP2MRMerkleRoot({leaf_hash});

    const CMutableTransaction tx_credit = BuildCreditingTransaction(BuildP2MROutput(merkle_root), /*nValue=*/50'000);
    CMutableTransaction tx_spend = BuildSpendingTransaction(CScript{}, CScriptWitness{}, CTransaction{tx_credit});

    const auto witness = BuildSignedSingleLeafP2MRWitness(tx_spend, tx_credit.vout.at(0), spend_key, leaf_script);
    BOOST_REQUIRE(witness.has_value());
    tx_spend.vin.at(0).scriptWitness = *witness;
    tx_spend.vin.at(0).scriptWitness.stack.back().push_back(0x00);

    CCoinsView coins_view;
    CCoinsViewCache coins_cache(&coins_view);
    AddCoins(coins_cache, CTransaction{tx_credit}, /*nHeight=*/0);

    std::string reason;
    BOOST_CHECK(!IsWitnessStandard(CTransaction{tx_spend}, coins_cache, "", reason));
    BOOST_CHECK_EQUAL(reason, "p2mr-control-size");
}

BOOST_AUTO_TEST_CASE(p2mr_witness_rejects_bad_leaf_script_shape)
{
    CPQKey spend_key;
    spend_key.MakeNewKey(PQAlgorithm::ML_DSA_44);
    BOOST_REQUIRE(spend_key.IsValid());

    const std::vector<unsigned char> leaf_script = BuildP2MRScript(PQAlgorithm::ML_DSA_44, spend_key.GetPubKey());
    const uint256 leaf_hash = ComputeP2MRLeafHash(P2MR_LEAF_VERSION, leaf_script);
    const uint256 merkle_root = ComputeP2MRMerkleRoot({leaf_hash});

    const CMutableTransaction tx_credit = BuildCreditingTransaction(BuildP2MROutput(merkle_root), /*nValue=*/50'000);
    CMutableTransaction tx_spend = BuildSpendingTransaction(CScript{}, CScriptWitness{}, CTransaction{tx_credit});

    const auto witness = BuildSignedSingleLeafP2MRWitness(tx_spend, tx_credit.vout.at(0), spend_key, leaf_script);
    BOOST_REQUIRE(witness.has_value());
    tx_spend.vin.at(0).scriptWitness = *witness;
    tx_spend.vin.at(0).scriptWitness.stack[1].back() = static_cast<unsigned char>(OP_TRUE);

    CCoinsView coins_view;
    CCoinsViewCache coins_cache(&coins_view);
    AddCoins(coins_cache, CTransaction{tx_credit}, /*nHeight=*/0);

    std::string reason;
    BOOST_CHECK(!IsWitnessStandard(CTransaction{tx_spend}, coins_cache, "", reason));
    BOOST_CHECK_EQUAL(reason, "p2mr-leaf-script");
}

BOOST_AUTO_TEST_CASE(p2mr_witness_rejects_bad_signature_size)
{
    CPQKey spend_key;
    spend_key.MakeNewKey(PQAlgorithm::ML_DSA_44);
    BOOST_REQUIRE(spend_key.IsValid());

    const std::vector<unsigned char> leaf_script = BuildP2MRScript(PQAlgorithm::ML_DSA_44, spend_key.GetPubKey());
    const uint256 leaf_hash = ComputeP2MRLeafHash(P2MR_LEAF_VERSION, leaf_script);
    const uint256 merkle_root = ComputeP2MRMerkleRoot({leaf_hash});

    const CMutableTransaction tx_credit = BuildCreditingTransaction(BuildP2MROutput(merkle_root), /*nValue=*/50'000);
    CMutableTransaction tx_spend = BuildSpendingTransaction(CScript{}, CScriptWitness{}, CTransaction{tx_credit});

    const auto witness = BuildSignedSingleLeafP2MRWitness(tx_spend, tx_credit.vout.at(0), spend_key, leaf_script);
    BOOST_REQUIRE(witness.has_value());
    tx_spend.vin.at(0).scriptWitness = *witness;
    tx_spend.vin.at(0).scriptWitness.stack[0].pop_back();

    CCoinsView coins_view;
    CCoinsViewCache coins_cache(&coins_view);
    AddCoins(coins_cache, CTransaction{tx_credit}, /*nHeight=*/0);

    std::string reason;
    BOOST_CHECK(!IsWitnessStandard(CTransaction{tx_spend}, coins_cache, "", reason));
    BOOST_CHECK_EQUAL(reason, "p2mr-signature-size");
}

BOOST_AUTO_TEST_CASE(p2mr_witness_rejects_invalid_signature_hashtype)
{
    CPQKey spend_key;
    spend_key.MakeNewKey(PQAlgorithm::ML_DSA_44);
    BOOST_REQUIRE(spend_key.IsValid());

    const std::vector<unsigned char> leaf_script = BuildP2MRScript(PQAlgorithm::ML_DSA_44, spend_key.GetPubKey());
    const uint256 leaf_hash = ComputeP2MRLeafHash(P2MR_LEAF_VERSION, leaf_script);
    const uint256 merkle_root = ComputeP2MRMerkleRoot({leaf_hash});

    const CMutableTransaction tx_credit = BuildCreditingTransaction(BuildP2MROutput(merkle_root), /*nValue=*/50'000);
    CMutableTransaction tx_spend = BuildSpendingTransaction(CScript{}, CScriptWitness{}, CTransaction{tx_credit});

    const auto witness = BuildSignedSingleLeafP2MRWitness(tx_spend, tx_credit.vout.at(0), spend_key, leaf_script);
    BOOST_REQUIRE(witness.has_value());
    tx_spend.vin.at(0).scriptWitness = *witness;
    tx_spend.vin.at(0).scriptWitness.stack[0].push_back(0x7f);

    CCoinsView coins_view;
    CCoinsViewCache coins_cache(&coins_view);
    AddCoins(coins_cache, CTransaction{tx_credit}, /*nHeight=*/0);

    std::string reason;
    BOOST_CHECK(!IsWitnessStandard(CTransaction{tx_spend}, coins_cache, "", reason));
    BOOST_CHECK_EQUAL(reason, "p2mr-signature-size");
}

BOOST_AUTO_TEST_CASE(p2mr_witness_rejects_explicit_default_signature_hashtype)
{
    CPQKey spend_key;
    spend_key.MakeNewKey(PQAlgorithm::ML_DSA_44);
    BOOST_REQUIRE(spend_key.IsValid());

    const std::vector<unsigned char> leaf_script = BuildP2MRScript(PQAlgorithm::ML_DSA_44, spend_key.GetPubKey());
    const uint256 leaf_hash = ComputeP2MRLeafHash(P2MR_LEAF_VERSION, leaf_script);
    const uint256 merkle_root = ComputeP2MRMerkleRoot({leaf_hash});

    const CMutableTransaction tx_credit = BuildCreditingTransaction(BuildP2MROutput(merkle_root), /*nValue=*/50'000);
    CMutableTransaction tx_spend = BuildSpendingTransaction(CScript{}, CScriptWitness{}, CTransaction{tx_credit});

    const auto witness = BuildSignedSingleLeafP2MRWitness(tx_spend, tx_credit.vout.at(0), spend_key, leaf_script);
    BOOST_REQUIRE(witness.has_value());
    tx_spend.vin.at(0).scriptWitness = *witness;
    tx_spend.vin.at(0).scriptWitness.stack[0].push_back(SIGHASH_DEFAULT);

    CCoinsView coins_view;
    CCoinsViewCache coins_cache(&coins_view);
    AddCoins(coins_cache, CTransaction{tx_credit}, /*nHeight=*/0);

    std::string reason;
    BOOST_CHECK(!IsWitnessStandard(CTransaction{tx_spend}, coins_cache, "", reason));
    BOOST_CHECK_EQUAL(reason, "p2mr-signature-size");
}

BOOST_AUTO_TEST_CASE(p2mr_witness_rejects_bad_leaf_version)
{
    CPQKey spend_key;
    spend_key.MakeNewKey(PQAlgorithm::ML_DSA_44);
    BOOST_REQUIRE(spend_key.IsValid());

    const std::vector<unsigned char> leaf_script = BuildP2MRScript(PQAlgorithm::ML_DSA_44, spend_key.GetPubKey());
    const uint256 leaf_hash = ComputeP2MRLeafHash(P2MR_LEAF_VERSION, leaf_script);
    const uint256 merkle_root = ComputeP2MRMerkleRoot({leaf_hash});

    const CMutableTransaction tx_credit = BuildCreditingTransaction(BuildP2MROutput(merkle_root), /*nValue=*/50'000);
    CMutableTransaction tx_spend = BuildSpendingTransaction(CScript{}, CScriptWitness{}, CTransaction{tx_credit});

    const auto witness = BuildSignedSingleLeafP2MRWitness(tx_spend, tx_credit.vout.at(0), spend_key, leaf_script);
    BOOST_REQUIRE(witness.has_value());
    tx_spend.vin.at(0).scriptWitness = *witness;
    tx_spend.vin.at(0).scriptWitness.stack.back().front() = 0xc0;

    CCoinsView coins_view;
    CCoinsViewCache coins_cache(&coins_view);
    AddCoins(coins_cache, CTransaction{tx_credit}, /*nHeight=*/0);

    std::string reason;
    BOOST_CHECK(!IsWitnessStandard(CTransaction{tx_spend}, coins_cache, "", reason));
    BOOST_CHECK_EQUAL(reason, "p2mr-leaf-version");
}

BOOST_AUTO_TEST_CASE(p2mr_transaction_accepted_by_mempool)
{
    CPQKey parent_spend_key;
    parent_spend_key.MakeNewKey(PQAlgorithm::ML_DSA_44);
    BOOST_REQUIRE(parent_spend_key.IsValid());

    CPQKey child_spend_key;
    child_spend_key.MakeNewKey(PQAlgorithm::ML_DSA_44);
    BOOST_REQUIRE(child_spend_key.IsValid());

    const std::vector<unsigned char> parent_leaf_script = BuildP2MRScript(PQAlgorithm::ML_DSA_44, parent_spend_key.GetPubKey());
    const std::vector<unsigned char> child_leaf_script = BuildP2MRScript(PQAlgorithm::ML_DSA_44, child_spend_key.GetPubKey());

    const uint256 parent_root = ComputeP2MRMerkleRoot({ComputeP2MRLeafHash(P2MR_LEAF_VERSION, parent_leaf_script)});
    const uint256 child_root = ComputeP2MRMerkleRoot({ComputeP2MRLeafHash(P2MR_LEAF_VERSION, child_leaf_script)});

    const CAmount parent_value = m_coinbase_txns.at(0)->vout.at(0).nValue - 10'000;
    BOOST_REQUIRE(parent_value > 0);

    const CMutableTransaction parent = CreateValidMempoolTransaction(
        m_coinbase_txns.at(0),
        /*input_vout=*/0,
        /*input_height=*/COINBASE_MATURITY,
        coinbaseKey,
        BuildP2MROutput(parent_root),
        parent_value,
        /*submit=*/true);

    CMutableTransaction child;
    child.vin.emplace_back(COutPoint{parent.GetHash(), 0}, CScript{}, MAX_BIP125_RBF_SEQUENCE);
    child.vout.emplace_back(parent_value - 20'000, BuildP2MROutput(child_root));

    const auto witness = BuildSignedSingleLeafP2MRWitness(child, parent.vout.at(0), parent_spend_key, parent_leaf_script);
    BOOST_REQUIRE(witness.has_value());
    child.vin.at(0).scriptWitness = *witness;

    const MempoolAcceptResult result = WITH_LOCK(cs_main, return m_node.chainman->ProcessTransaction(MakeTransactionRef(child)););
    BOOST_CHECK_MESSAGE(
        result.m_result_type == MempoolAcceptResult::ResultType::VALID,
        "Unexpected mempool result: " << static_cast<int>(result.m_result_type)
                                      << " state=" << result.m_state.ToString());
}

BOOST_AUTO_TEST_CASE(p2mr_csfs_witness_rejects_oversized_message_policy)
{
    CPQKey oracle_key;
    oracle_key.MakeNewKey(PQAlgorithm::ML_DSA_44);
    BOOST_REQUIRE(oracle_key.IsValid());

    const std::vector<unsigned char> leaf_script = BuildP2MRCSFSScript(PQAlgorithm::ML_DSA_44, oracle_key.GetPubKey());
    const uint256 leaf_hash = ComputeP2MRLeafHash(P2MR_LEAF_VERSION, leaf_script);
    const uint256 merkle_root = ComputeP2MRMerkleRoot({leaf_hash});

    const CMutableTransaction tx_credit = BuildCreditingTransaction(BuildP2MROutput(merkle_root), /*nValue=*/50'000);
    CMutableTransaction tx_spend = BuildSpendingTransaction(CScript{}, CScriptWitness{}, CTransaction{tx_credit});

    const std::vector<unsigned char> msg(521, 0x01);
    const std::vector<unsigned char> sig_csfs = SignCSFSMessage(oracle_key, msg);
    tx_spend.vin.at(0).scriptWitness.stack = {sig_csfs, msg, leaf_script, {P2MR_LEAF_VERSION}};

    CCoinsView coins_view;
    CCoinsViewCache coins_cache(&coins_view);
    AddCoins(coins_cache, CTransaction{tx_credit}, /*nHeight=*/0);

    std::string reason;
    BOOST_CHECK(!IsWitnessStandard(CTransaction{tx_spend}, coins_cache, "", reason));
    BOOST_CHECK_EQUAL(reason, "p2mr-csfs-msg-size");
}

BOOST_AUTO_TEST_CASE(p2mr_csfs_signature_plus_hashtype_rejected_by_policy)
{
    CPQKey oracle_key;
    oracle_key.MakeNewKey(PQAlgorithm::ML_DSA_44);
    BOOST_REQUIRE(oracle_key.IsValid());

    const std::vector<unsigned char> leaf_script = BuildP2MRCSFSScript(PQAlgorithm::ML_DSA_44, oracle_key.GetPubKey());
    const uint256 leaf_hash = ComputeP2MRLeafHash(P2MR_LEAF_VERSION, leaf_script);
    const uint256 merkle_root = ComputeP2MRMerkleRoot({leaf_hash});

    const CMutableTransaction tx_credit = BuildCreditingTransaction(BuildP2MROutput(merkle_root), /*nValue=*/50'000);
    CMutableTransaction tx_spend = BuildSpendingTransaction(CScript{}, CScriptWitness{}, CTransaction{tx_credit});

    const std::vector<unsigned char> msg{0x42, 0x43};
    std::vector<unsigned char> sig_csfs = SignCSFSMessage(oracle_key, msg);
    sig_csfs.push_back(SIGHASH_DEFAULT);
    tx_spend.vin.at(0).scriptWitness.stack = {sig_csfs, msg, leaf_script, {P2MR_LEAF_VERSION}};

    CCoinsView coins_view;
    CCoinsViewCache coins_cache(&coins_view);
    AddCoins(coins_cache, CTransaction{tx_credit}, /*nHeight=*/0);

    std::string reason;
    BOOST_CHECK(!IsWitnessStandard(CTransaction{tx_spend}, coins_cache, "", reason));
    BOOST_CHECK_EQUAL(reason, "p2mr-csfs-signature-size");
}

BOOST_AUTO_TEST_CASE(p2mr_csfs_slhdsa_only_witness_is_standard)
{
    CPQKey oracle_key;
    oracle_key.MakeNewKey(PQAlgorithm::SLH_DSA_128S);
    BOOST_REQUIRE(oracle_key.IsValid());

    const std::vector<unsigned char> leaf_script = BuildP2MRCSFSScript(PQAlgorithm::SLH_DSA_128S, oracle_key.GetPubKey());
    const uint256 leaf_hash = ComputeP2MRLeafHash(P2MR_LEAF_VERSION, leaf_script);
    const uint256 merkle_root = ComputeP2MRMerkleRoot({leaf_hash});

    const CMutableTransaction tx_credit = BuildCreditingTransaction(BuildP2MROutput(merkle_root), /*nValue=*/50'000);
    CMutableTransaction tx_spend = BuildSpendingTransaction(CScript{}, CScriptWitness{}, CTransaction{tx_credit});

    const std::vector<unsigned char> msg{0x01, 0x02, 0x03};
    const std::vector<unsigned char> sig_csfs = SignCSFSMessage(oracle_key, msg);
    tx_spend.vin.at(0).scriptWitness.stack = {sig_csfs, msg, leaf_script, {P2MR_LEAF_VERSION}};

    CCoinsView coins_view;
    CCoinsViewCache coins_cache(&coins_view);
    AddCoins(coins_cache, CTransaction{tx_credit}, /*nHeight=*/0);

    std::string reason;
    BOOST_CHECK(IsWitnessStandard(CTransaction{tx_spend}, coins_cache, "", reason));
}

BOOST_AUTO_TEST_CASE(p2mr_csfs_slhdsa_witness_rejects_oversized_message_policy)
{
    CPQKey oracle_key;
    oracle_key.MakeNewKey(PQAlgorithm::SLH_DSA_128S);
    BOOST_REQUIRE(oracle_key.IsValid());

    const std::vector<unsigned char> leaf_script = BuildP2MRCSFSScript(PQAlgorithm::SLH_DSA_128S, oracle_key.GetPubKey());
    const uint256 leaf_hash = ComputeP2MRLeafHash(P2MR_LEAF_VERSION, leaf_script);
    const uint256 merkle_root = ComputeP2MRMerkleRoot({leaf_hash});

    const CMutableTransaction tx_credit = BuildCreditingTransaction(BuildP2MROutput(merkle_root), /*nValue=*/50'000);
    CMutableTransaction tx_spend = BuildSpendingTransaction(CScript{}, CScriptWitness{}, CTransaction{tx_credit});

    const std::vector<unsigned char> msg(521, 0x01);
    const std::vector<unsigned char> sig_csfs = SignCSFSMessage(oracle_key, msg);
    tx_spend.vin.at(0).scriptWitness.stack = {sig_csfs, msg, leaf_script, {P2MR_LEAF_VERSION}};

    CCoinsView coins_view;
    CCoinsViewCache coins_cache(&coins_view);
    AddCoins(coins_cache, CTransaction{tx_credit}, /*nHeight=*/0);

    std::string reason;
    BOOST_CHECK(!IsWitnessStandard(CTransaction{tx_spend}, coins_cache, "", reason));
    BOOST_CHECK_EQUAL(reason, "p2mr-csfs-msg-size");
}

BOOST_AUTO_TEST_CASE(p2mr_csfs_slhdsa_signature_plus_hashtype_rejected_by_policy)
{
    CPQKey oracle_key;
    oracle_key.MakeNewKey(PQAlgorithm::SLH_DSA_128S);
    BOOST_REQUIRE(oracle_key.IsValid());

    const std::vector<unsigned char> leaf_script = BuildP2MRCSFSScript(PQAlgorithm::SLH_DSA_128S, oracle_key.GetPubKey());
    const uint256 leaf_hash = ComputeP2MRLeafHash(P2MR_LEAF_VERSION, leaf_script);
    const uint256 merkle_root = ComputeP2MRMerkleRoot({leaf_hash});

    const CMutableTransaction tx_credit = BuildCreditingTransaction(BuildP2MROutput(merkle_root), /*nValue=*/50'000);
    CMutableTransaction tx_spend = BuildSpendingTransaction(CScript{}, CScriptWitness{}, CTransaction{tx_credit});

    const std::vector<unsigned char> msg{0x42, 0x43};
    std::vector<unsigned char> sig_csfs = SignCSFSMessage(oracle_key, msg);
    sig_csfs.push_back(SIGHASH_DEFAULT);
    tx_spend.vin.at(0).scriptWitness.stack = {sig_csfs, msg, leaf_script, {P2MR_LEAF_VERSION}};

    CCoinsView coins_view;
    CCoinsViewCache coins_cache(&coins_view);
    AddCoins(coins_cache, CTransaction{tx_credit}, /*nHeight=*/0);

    std::string reason;
    BOOST_CHECK(!IsWitnessStandard(CTransaction{tx_spend}, coins_cache, "", reason));
    BOOST_CHECK_EQUAL(reason, "p2mr-csfs-signature-size");
}

BOOST_AUTO_TEST_CASE(p2mr_two_mldsa_delegation_leaf_rejected_by_policy_limit)
{
    CPQKey oracle_key;
    oracle_key.MakeNewKey(PQAlgorithm::ML_DSA_44);
    BOOST_REQUIRE(oracle_key.IsValid());
    CPQKey spender_key;
    spender_key.MakeNewKey(PQAlgorithm::ML_DSA_44);
    BOOST_REQUIRE(spender_key.IsValid());

    const std::vector<unsigned char> leaf_script = BuildP2MRDelegationScript(
        PQAlgorithm::ML_DSA_44, oracle_key.GetPubKey(),
        PQAlgorithm::ML_DSA_44, spender_key.GetPubKey());
    BOOST_CHECK_GT(leaf_script.size(), g_script_size_policy_limit);

    const uint256 leaf_hash = ComputeP2MRLeafHash(P2MR_LEAF_VERSION, leaf_script);
    const uint256 merkle_root = ComputeP2MRMerkleRoot({leaf_hash});

    const CMutableTransaction tx_credit = BuildCreditingTransaction(BuildP2MROutput(merkle_root), /*nValue=*/50'000);
    CMutableTransaction tx_spend = BuildSpendingTransaction(CScript{}, CScriptWitness{}, CTransaction{tx_credit});

    const auto checksig_witness = BuildSignedSingleLeafP2MRWitness(tx_spend, tx_credit.vout.at(0), spender_key, leaf_script);
    BOOST_REQUIRE(checksig_witness.has_value());
    tx_spend.vin.at(0).scriptWitness = *checksig_witness;
    const std::vector<unsigned char> msg{0x01, 0x02};
    tx_spend.vin.at(0).scriptWitness.stack.insert(tx_spend.vin.at(0).scriptWitness.stack.begin() + 1, SignCSFSMessage(oracle_key, msg));
    tx_spend.vin.at(0).scriptWitness.stack.insert(tx_spend.vin.at(0).scriptWitness.stack.begin() + 2, msg);

    CCoinsView coins_view;
    CCoinsViewCache coins_cache(&coins_view);
    AddCoins(coins_cache, CTransaction{tx_credit}, /*nHeight=*/0);

    std::string reason;
    BOOST_CHECK(!IsWitnessStandard(CTransaction{tx_spend}, coins_cache, "", reason));
    BOOST_CHECK_EQUAL(reason, "p2mr-script-size");
}

BOOST_AUTO_TEST_CASE(p2mr_policy_stack_size_six_and_one_rejected)
{
    CPQKey spend_key;
    spend_key.MakeNewKey(PQAlgorithm::ML_DSA_44);
    BOOST_REQUIRE(spend_key.IsValid());

    const std::vector<unsigned char> leaf_script = BuildP2MRScript(PQAlgorithm::ML_DSA_44, spend_key.GetPubKey());
    const uint256 leaf_hash = ComputeP2MRLeafHash(P2MR_LEAF_VERSION, leaf_script);
    const uint256 merkle_root = ComputeP2MRMerkleRoot({leaf_hash});

    const CMutableTransaction tx_credit = BuildCreditingTransaction(BuildP2MROutput(merkle_root), /*nValue=*/50'000);
    CMutableTransaction tx_spend = BuildSpendingTransaction(CScript{}, CScriptWitness{}, CTransaction{tx_credit});

    const auto witness = BuildSignedSingleLeafP2MRWitness(tx_spend, tx_credit.vout.at(0), spend_key, leaf_script);
    BOOST_REQUIRE(witness.has_value());

    {
        CMutableTransaction tx = tx_spend;
        tx.vin.at(0).scriptWitness = *witness;
        tx.vin.at(0).scriptWitness.stack.insert(tx.vin.at(0).scriptWitness.stack.begin(), std::vector<unsigned char>{0x01});
        tx.vin.at(0).scriptWitness.stack.insert(tx.vin.at(0).scriptWitness.stack.begin(), std::vector<unsigned char>{0x02});
        tx.vin.at(0).scriptWitness.stack.insert(tx.vin.at(0).scriptWitness.stack.begin(), std::vector<unsigned char>{0x03});

        CCoinsView coins_view;
        CCoinsViewCache coins_cache(&coins_view);
        AddCoins(coins_cache, CTransaction{tx_credit}, /*nHeight=*/0);
        std::string reason;
        BOOST_CHECK(!IsWitnessStandard(CTransaction{tx}, coins_cache, "", reason));
        BOOST_CHECK_EQUAL(reason, "p2mr-stack-size");
    }

    {
        CMutableTransaction tx = tx_spend;
        tx.vin.at(0).scriptWitness.stack = {leaf_script};

        CCoinsView coins_view;
        CCoinsViewCache coins_cache(&coins_view);
        AddCoins(coins_cache, CTransaction{tx_credit}, /*nHeight=*/0);
        std::string reason;
        BOOST_CHECK(!IsWitnessStandard(CTransaction{tx}, coins_cache, "", reason));
        BOOST_CHECK_EQUAL(reason, "p2mr-witness-missing");
    }
}

BOOST_AUTO_TEST_SUITE_END()
