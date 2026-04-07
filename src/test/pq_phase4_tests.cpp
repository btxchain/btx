// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <hash.h>
#include <external_signer.h>
#include <key.h>
#include <psbt.h>
#include <pqkey.h>
#include <script/ctv.h>
#include <script/interpreter.h>
#include <script/pqm.h>
#include <script/sign.h>
#include <script/signingprovider.h>
#include <test/util/setup_common.h>
#include <test/util/transaction_utils.h>
#include <tinyformat.h>
#include <util/fs.h>
#include <util/strencodings.h>
#include <wallet/pq_keyderivation.h>

#include <boost/test/unit_test.hpp>

#include <algorithm>
#include <cassert>
#include <chrono>
#include <fstream>
#include <optional>
#include <utility>
#include <vector>

namespace {

CScript BuildP2MROutput(const uint256& merkle_root)
{
    CScript script;
    script << OP_2 << ToByteVector(merkle_root);
    return script;
}

uint256 ConfigureSingleLeafP2MRInput(PSBTInput& input, std::vector<unsigned char> leaf_script)
{
    input.m_p2mr_leaf_script = std::move(leaf_script);
    input.m_p2mr_control_block = {P2MR_LEAF_VERSION};
    input.m_p2mr_leaf_version = P2MR_LEAF_VERSION;
    const uint256 leaf_hash = ComputeP2MRLeafHash(P2MR_LEAF_VERSION, input.m_p2mr_leaf_script);
    const uint256 merkle_root = ComputeP2MRMerkleRoot({leaf_hash});
    input.m_p2mr_merkle_root = merkle_root;
    return merkle_root;
}

struct P2MRSignContext {
    CMutableTransaction tx_credit;
    CMutableTransaction tx_spend;
    PrecomputedTransactionData txdata;
    uint256 merkle_root;

    explicit P2MRSignContext(Span<const unsigned char> leaf_script)
    {
        const uint256 leaf_hash = ComputeP2MRLeafHash(P2MR_LEAF_VERSION, leaf_script);
        merkle_root = ComputeP2MRMerkleRoot({leaf_hash});
        tx_credit = BuildCreditingTransaction(BuildP2MROutput(merkle_root), /*nValue=*/5'000);
        tx_spend = BuildSpendingTransaction(CScript{}, CScriptWitness{}, CTransaction{tx_credit});
        txdata.Init(tx_spend, {tx_credit.vout.at(0)}, /*force=*/true);
    }
};

std::optional<uint256> ComputeP2MRSighash(
    const CMutableTransaction& tx_spend,
    const PrecomputedTransactionData& txdata,
    Span<const unsigned char> leaf_script)
{
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
            tx_spend,
            /*in_pos=*/0,
            SIGHASH_DEFAULT,
            SigVersion::P2MR,
            txdata,
            MissingDataBehavior::ASSERT_FAIL)) {
        return std::nullopt;
    }
    return sighash;
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

FlatSigningProvider BuildSingleLeafProvider(
    const uint256& merkle_root,
    const std::vector<unsigned char>& leaf_script,
    const std::optional<CPQKey>& key = std::nullopt)
{
    FlatSigningProvider provider;
    P2MRSpendData spenddata;
    spenddata.scripts[leaf_script].insert({P2MR_LEAF_VERSION});
    provider.p2mr_spends[WitnessV2P2MR{merkle_root}] = spenddata;
    if (key.has_value()) {
        provider.pq_keys[key->GetPubKey()] = *key;
    }
    return provider;
}

FlatSigningProvider BuildSingleLeafProviderWithKeys(
    const uint256& merkle_root,
    const std::vector<unsigned char>& leaf_script,
    const std::vector<CPQKey>& keys)
{
    FlatSigningProvider provider;
    P2MRSpendData spenddata;
    spenddata.scripts[leaf_script].insert({P2MR_LEAF_VERSION});
    provider.p2mr_spends[WitnessV2P2MR{merkle_root}] = spenddata;
    for (const auto& key : keys) {
        provider.pq_keys[key.GetPubKey()] = key;
    }
    return provider;
}

std::vector<unsigned char> SerializeP2MRKeyOrigin(
    const std::array<unsigned char, 4>& fingerprint,
    const std::vector<uint32_t>& path)
{
    KeyOriginInfo origin;
    std::copy(fingerprint.begin(), fingerprint.end(), origin.fingerprint);
    origin.path = path;
    std::vector<unsigned char> encoded;
    VectorWriter writer{encoded, 0};
    SerializeKeyOrigin(writer, origin);
    return encoded;
}

std::string EncodePSBTForMockSigner(const PartiallySignedTransaction& psbt)
{
    DataStream ss{};
    ss << psbt;
    return EncodeBase64(ss.str());
}

fs::path WriteStaticMockSignerScriptResponse(const std::string& json_response)
{
    const auto unique = std::chrono::steady_clock::now().time_since_epoch().count();
    const fs::path script_path = fs::temp_directory_path() / strprintf("btx_mock_signer_%lld.sh", static_cast<long long>(unique));
    std::ofstream script_file(script_path);
    script_file << "#!/bin/sh\n";
    script_file << "cat <<'EOF'\n";
    script_file << json_response << "\n";
    script_file << "EOF\n";
    script_file.close();
    return script_path;
}

fs::path WriteFailingMockSignerScript()
{
    const auto unique = std::chrono::steady_clock::now().time_since_epoch().count();
    const fs::path script_path = fs::temp_directory_path() / strprintf("btx_mock_signer_fail_%lld.sh", static_cast<long long>(unique));
    std::ofstream script_file(script_path);
    script_file << "#!/bin/sh\n";
    script_file << "cat >/dev/null\n";
    script_file << "echo mock signer failed >&2\n";
    script_file << "exit 1\n";
    script_file.close();
    return script_path;
}

fs::path WriteArgDumpMockSignerScript()
{
    const auto unique = std::chrono::steady_clock::now().time_since_epoch().count();
    const fs::path script_path = fs::temp_directory_path() / strprintf("btx_mock_signer_args_%lld.sh", static_cast<long long>(unique));
    std::ofstream script_file(script_path);
    script_file << "#!/bin/sh\n";
    script_file << "set -eu\n";
    script_file << "first=1\n";
    script_file << "out='{\"argv\":\"'\n";
    script_file << "for arg in \"$@\"; do\n";
    script_file << "  if [ \"$first\" -eq 0 ]; then\n";
    script_file << "    out=\"${out}|\"\n";
    script_file << "  fi\n";
    script_file << "  first=0\n";
    script_file << "  out=\"${out}${arg}\"\n";
    script_file << "done\n";
    script_file << "out=\"${out}\\\"}\"\n";
    script_file << "echo \"$out\"\n";
    script_file.close();
    return script_path;
}

} // namespace

BOOST_FIXTURE_TEST_SUITE(pq_phase4_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(signp2mr_ctv_only_witness_has_two_items)
{
    const CMutableTransaction tmp_credit = BuildCreditingTransaction(BuildP2MROutput(uint256::ONE), /*nValue=*/5'000);
    const CMutableTransaction tmp_spend = BuildSpendingTransaction(CScript{}, CScriptWitness{}, CTransaction{tmp_credit});
    PrecomputedTransactionData tmp_txdata;
    tmp_txdata.Init(tmp_spend, {tmp_credit.vout.at(0)}, /*force=*/true);
    const uint256 ctv_hash = ComputeCTVHash(CTransaction{tmp_spend}, /*nIn=*/0, tmp_txdata);

    const std::vector<unsigned char> leaf_script = BuildP2MRCTVScript(ctv_hash);
    P2MRSignContext ctx{leaf_script};
    FlatSigningProvider provider = BuildSingleLeafProvider(ctx.merkle_root, leaf_script);

    MutableTransactionSignatureCreator creator(
        ctx.tx_spend, /*input_idx=*/0, ctx.tx_credit.vout.at(0).nValue, &ctx.txdata, SIGHASH_DEFAULT);
    SignatureData sigdata;
    BOOST_REQUIRE(ProduceSignature(provider, creator, ctx.tx_credit.vout.at(0).scriptPubKey, sigdata));
    BOOST_REQUIRE_EQUAL(sigdata.scriptWitness.stack.size(), 2U);
    BOOST_CHECK(sigdata.scriptWitness.stack[0] == leaf_script);
    BOOST_CHECK(sigdata.scriptWitness.stack[1] == std::vector<unsigned char>({P2MR_LEAF_VERSION}));
}

BOOST_AUTO_TEST_CASE(signp2mr_ctv_checksig_witness_has_three_items)
{
    CPQKey key;
    key.MakeNewKey(PQAlgorithm::ML_DSA_44);
    BOOST_REQUIRE(key.IsValid());

    const CMutableTransaction tmp_credit = BuildCreditingTransaction(BuildP2MROutput(uint256::ONE), /*nValue=*/5'000);
    const CMutableTransaction tmp_spend = BuildSpendingTransaction(CScript{}, CScriptWitness{}, CTransaction{tmp_credit});
    PrecomputedTransactionData tmp_txdata;
    tmp_txdata.Init(tmp_spend, {tmp_credit.vout.at(0)}, /*force=*/true);
    const uint256 ctv_hash = ComputeCTVHash(CTransaction{tmp_spend}, /*nIn=*/0, tmp_txdata);

    const std::vector<unsigned char> leaf_script = BuildP2MRCTVChecksigScript(ctv_hash, PQAlgorithm::ML_DSA_44, key.GetPubKey());
    P2MRSignContext ctx{leaf_script};
    FlatSigningProvider provider = BuildSingleLeafProvider(ctx.merkle_root, leaf_script, key);

    MutableTransactionSignatureCreator creator(
        ctx.tx_spend, /*input_idx=*/0, ctx.tx_credit.vout.at(0).nValue, &ctx.txdata, SIGHASH_DEFAULT);
    SignatureData sigdata;
    BOOST_REQUIRE(ProduceSignature(provider, creator, ctx.tx_credit.vout.at(0).scriptPubKey, sigdata));
    BOOST_REQUIRE_EQUAL(sigdata.scriptWitness.stack.size(), 3U);
    BOOST_CHECK(sigdata.scriptWitness.stack[1] == leaf_script);
    BOOST_CHECK(sigdata.scriptWitness.stack[2] == std::vector<unsigned char>({P2MR_LEAF_VERSION}));
}

BOOST_AUTO_TEST_CASE(signp2mr_cltv_multisig_witness_has_keycount_plus_two_items)
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
    P2MRSignContext ctx{leaf_script};
    ctx.tx_spend.nLockTime = 700;
    ctx.tx_spend.vin.at(0).nSequence = CTxIn::SEQUENCE_FINAL - 1;
    ctx.txdata = PrecomputedTransactionData{};
    ctx.txdata.Init(ctx.tx_spend, {ctx.tx_credit.vout.at(0)}, /*force=*/true);
    const FlatSigningProvider provider = BuildSingleLeafProviderWithKeys(ctx.merkle_root, leaf_script, {key1, key3});

    MutableTransactionSignatureCreator creator(
        ctx.tx_spend, /*input_idx=*/0, ctx.tx_credit.vout.at(0).nValue, &ctx.txdata, SIGHASH_DEFAULT);
    SignatureData sigdata;
    BOOST_REQUIRE(ProduceSignature(provider, creator, ctx.tx_credit.vout.at(0).scriptPubKey, sigdata));
    BOOST_REQUIRE_EQUAL(sigdata.scriptWitness.stack.size(), 5U);
    const size_t non_empty_sigs = (!sigdata.scriptWitness.stack[0].empty() ? 1U : 0U) +
                                  (!sigdata.scriptWitness.stack[1].empty() ? 1U : 0U) +
                                  (!sigdata.scriptWitness.stack[2].empty() ? 1U : 0U);
    BOOST_CHECK_EQUAL(non_empty_sigs, 2U);
    BOOST_CHECK(sigdata.scriptWitness.stack[3] == leaf_script);
    BOOST_CHECK(sigdata.scriptWitness.stack[4] == std::vector<unsigned char>({P2MR_LEAF_VERSION}));
}

BOOST_AUTO_TEST_CASE(signp2mr_csv_multisig_witness_has_keycount_plus_two_items)
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
    P2MRSignContext ctx{leaf_script};
    ctx.tx_spend.version = 2;
    ctx.tx_spend.vin.at(0).nSequence = 144;
    ctx.txdata = PrecomputedTransactionData{};
    ctx.txdata.Init(ctx.tx_spend, {ctx.tx_credit.vout.at(0)}, /*force=*/true);
    const FlatSigningProvider provider = BuildSingleLeafProviderWithKeys(ctx.merkle_root, leaf_script, {key1, key3});

    MutableTransactionSignatureCreator creator(
        ctx.tx_spend, /*input_idx=*/0, ctx.tx_credit.vout.at(0).nValue, &ctx.txdata, SIGHASH_DEFAULT);
    SignatureData sigdata;
    BOOST_REQUIRE(ProduceSignature(provider, creator, ctx.tx_credit.vout.at(0).scriptPubKey, sigdata));
    BOOST_REQUIRE_EQUAL(sigdata.scriptWitness.stack.size(), 5U);
    const size_t non_empty_sigs = (!sigdata.scriptWitness.stack[0].empty() ? 1U : 0U) +
                                  (!sigdata.scriptWitness.stack[1].empty() ? 1U : 0U) +
                                  (!sigdata.scriptWitness.stack[2].empty() ? 1U : 0U);
    BOOST_CHECK_EQUAL(non_empty_sigs, 2U);
    BOOST_CHECK(sigdata.scriptWitness.stack[3] == leaf_script);
    BOOST_CHECK(sigdata.scriptWitness.stack[4] == std::vector<unsigned char>({P2MR_LEAF_VERSION}));
}

BOOST_AUTO_TEST_CASE(signp2mr_csfs_only_without_sigdata_material_fails)
{
    CPQKey oracle_key;
    oracle_key.MakeNewKey(PQAlgorithm::ML_DSA_44);
    BOOST_REQUIRE(oracle_key.IsValid());

    const std::vector<unsigned char> leaf_script = BuildP2MRCSFSScript(PQAlgorithm::ML_DSA_44, oracle_key.GetPubKey());
    P2MRSignContext ctx{leaf_script};
    FlatSigningProvider provider = BuildSingleLeafProvider(ctx.merkle_root, leaf_script);

    MutableTransactionSignatureCreator creator(
        ctx.tx_spend, /*input_idx=*/0, ctx.tx_credit.vout.at(0).nValue, &ctx.txdata, SIGHASH_DEFAULT);
    SignatureData sigdata;
    BOOST_CHECK(!ProduceSignature(provider, creator, ctx.tx_credit.vout.at(0).scriptPubKey, sigdata));
}

BOOST_AUTO_TEST_CASE(signp2mr_csfs_verify_checksig_witness_has_five_items)
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
    P2MRSignContext ctx{leaf_script};
    FlatSigningProvider provider = BuildSingleLeafProvider(ctx.merkle_root, leaf_script, spender_key);

    const uint256 leaf_hash = ComputeP2MRLeafHash(P2MR_LEAF_VERSION, leaf_script);
    const std::vector<unsigned char> msg{0x10, 0x20};
    SignatureData sigdata;
    sigdata.p2mr_csfs_msgs[std::make_pair(leaf_hash, oracle_key.GetPubKey())] = msg;
    sigdata.p2mr_csfs_sigs[std::make_pair(leaf_hash, oracle_key.GetPubKey())] = CreateCSFSSignature(oracle_key, msg);

    MutableTransactionSignatureCreator creator(
        ctx.tx_spend, /*input_idx=*/0, ctx.tx_credit.vout.at(0).nValue, &ctx.txdata, SIGHASH_DEFAULT);
    BOOST_REQUIRE(ProduceSignature(provider, creator, ctx.tx_credit.vout.at(0).scriptPubKey, sigdata));
    BOOST_REQUIRE_EQUAL(sigdata.scriptWitness.stack.size(), 5U);
    BOOST_CHECK(sigdata.scriptWitness.stack[2] == msg);
    BOOST_CHECK(sigdata.scriptWitness.stack[3] == leaf_script);
    BOOST_CHECK(sigdata.scriptWitness.stack[4] == std::vector<unsigned char>({P2MR_LEAF_VERSION}));
}

BOOST_AUTO_TEST_CASE(signp2mr_prefers_existing_sigdata_signature)
{
    CPQKey key;
    key.MakeNewKey(PQAlgorithm::ML_DSA_44);
    BOOST_REQUIRE(key.IsValid());
    const std::vector<unsigned char> leaf_script = BuildP2MRScript(PQAlgorithm::ML_DSA_44, key.GetPubKey());
    P2MRSignContext ctx{leaf_script};
    FlatSigningProvider provider = BuildSingleLeafProvider(ctx.merkle_root, leaf_script);

    const auto sighash = ComputeP2MRSighash(ctx.tx_spend, ctx.txdata, leaf_script);
    BOOST_REQUIRE(sighash.has_value());
    std::vector<unsigned char> existing_sig;
    BOOST_REQUIRE(key.Sign(*sighash, existing_sig));

    const uint256 leaf_hash = ComputeP2MRLeafHash(P2MR_LEAF_VERSION, leaf_script);
    SignatureData sigdata;
    sigdata.p2mr_script_sigs[std::make_pair(leaf_hash, key.GetPubKey())] = existing_sig;

    MutableTransactionSignatureCreator creator(
        ctx.tx_spend, /*input_idx=*/0, ctx.tx_credit.vout.at(0).nValue, &ctx.txdata, SIGHASH_DEFAULT);
    BOOST_REQUIRE(ProduceSignature(provider, creator, ctx.tx_credit.vout.at(0).scriptPubKey, sigdata));
    BOOST_REQUIRE_EQUAL(sigdata.scriptWitness.stack.size(), 3U);
    BOOST_CHECK(sigdata.scriptWitness.stack[0] == existing_sig);
}

BOOST_AUTO_TEST_CASE(signp2mr_falls_back_to_createpqsig_when_sigdata_empty)
{
    CPQKey key;
    key.MakeNewKey(PQAlgorithm::ML_DSA_44);
    BOOST_REQUIRE(key.IsValid());
    const std::vector<unsigned char> leaf_script = BuildP2MRScript(PQAlgorithm::ML_DSA_44, key.GetPubKey());
    P2MRSignContext ctx{leaf_script};
    FlatSigningProvider provider = BuildSingleLeafProvider(ctx.merkle_root, leaf_script, key);
    const uint256 leaf_hash = ComputeP2MRLeafHash(P2MR_LEAF_VERSION, leaf_script);

    MutableTransactionSignatureCreator creator(
        ctx.tx_spend, /*input_idx=*/0, ctx.tx_credit.vout.at(0).nValue, &ctx.txdata, SIGHASH_DEFAULT);
    SignatureData sigdata;
    BOOST_REQUIRE(ProduceSignature(provider, creator, ctx.tx_credit.vout.at(0).scriptPubKey, sigdata));

    const auto it = sigdata.p2mr_script_sigs.find(std::make_pair(leaf_hash, key.GetPubKey()));
    BOOST_REQUIRE(it != sigdata.p2mr_script_sigs.end());
    BOOST_CHECK(sigdata.scriptWitness.stack[0] == it->second);
}

BOOST_AUTO_TEST_CASE(signp2mr_prefers_mldsa_leaf_by_default_when_multiple_checksig_leaves_exist)
{
    CPQKey ml_key;
    ml_key.MakeNewKey(PQAlgorithm::ML_DSA_44);
    BOOST_REQUIRE(ml_key.IsValid());
    CPQKey slh_key;
    slh_key.MakeNewKey(PQAlgorithm::SLH_DSA_128S);
    BOOST_REQUIRE(slh_key.IsValid());

    const std::vector<unsigned char> ml_leaf_script = BuildP2MRScript(PQAlgorithm::ML_DSA_44, ml_key.GetPubKey());
    const std::vector<unsigned char> slh_leaf_script = BuildP2MRScript(PQAlgorithm::SLH_DSA_128S, slh_key.GetPubKey());
    const uint256 ml_leaf_hash = ComputeP2MRLeafHash(P2MR_LEAF_VERSION, ml_leaf_script);
    const uint256 slh_leaf_hash = ComputeP2MRLeafHash(P2MR_LEAF_VERSION, slh_leaf_script);
    const uint256 merkle_root = ComputeP2MRMerkleRoot({
        ml_leaf_hash,
        slh_leaf_hash,
    });

    const CMutableTransaction tx_credit = BuildCreditingTransaction(BuildP2MROutput(merkle_root), /*nValue=*/5'000);
    CMutableTransaction tx_spend = BuildSpendingTransaction(CScript{}, CScriptWitness{}, CTransaction{tx_credit});
    PrecomputedTransactionData txdata;
    txdata.Init(tx_spend, {tx_credit.vout.at(0)}, /*force=*/true);

    FlatSigningProvider provider;
    P2MRSpendData spenddata;
    std::vector<unsigned char> ml_control{P2MR_LEAF_VERSION};
    ml_control.insert(ml_control.end(), slh_leaf_hash.begin(), slh_leaf_hash.end());
    spenddata.scripts[ml_leaf_script].insert(ml_control);
    std::vector<unsigned char> slh_control{P2MR_LEAF_VERSION};
    slh_control.insert(slh_control.end(), ml_leaf_hash.begin(), ml_leaf_hash.end());
    spenddata.scripts[slh_leaf_script].insert(slh_control);
    provider.p2mr_spends[WitnessV2P2MR{merkle_root}] = spenddata;
    provider.pq_keys[ml_key.GetPubKey()] = ml_key;
    provider.pq_keys[slh_key.GetPubKey()] = slh_key;

    MutableTransactionSignatureCreator creator(
        tx_spend, /*input_idx=*/0, tx_credit.vout.at(0).nValue, &txdata, SIGHASH_DEFAULT);
    SignatureData sigdata;
    BOOST_REQUIRE(ProduceSignature(provider, creator, tx_credit.vout.at(0).scriptPubKey, sigdata));
    BOOST_REQUIRE_EQUAL(sigdata.scriptWitness.stack.size(), 3U);
    BOOST_CHECK(sigdata.scriptWitness.stack[1] == ml_leaf_script);
    BOOST_CHECK_EQUAL(sigdata.scriptWitness.stack[0].size(), MLDSA44_SIGNATURE_SIZE);
}

BOOST_AUTO_TEST_CASE(signp2mr_prefers_slhdsa_leaf_when_requested)
{
    CPQKey ml_key;
    ml_key.MakeNewKey(PQAlgorithm::ML_DSA_44);
    BOOST_REQUIRE(ml_key.IsValid());
    CPQKey slh_key;
    slh_key.MakeNewKey(PQAlgorithm::SLH_DSA_128S);
    BOOST_REQUIRE(slh_key.IsValid());

    const std::vector<unsigned char> ml_leaf_script = BuildP2MRScript(PQAlgorithm::ML_DSA_44, ml_key.GetPubKey());
    const std::vector<unsigned char> slh_leaf_script = BuildP2MRScript(PQAlgorithm::SLH_DSA_128S, slh_key.GetPubKey());
    const uint256 ml_leaf_hash = ComputeP2MRLeafHash(P2MR_LEAF_VERSION, ml_leaf_script);
    const uint256 slh_leaf_hash = ComputeP2MRLeafHash(P2MR_LEAF_VERSION, slh_leaf_script);
    const uint256 merkle_root = ComputeP2MRMerkleRoot({
        ml_leaf_hash,
        slh_leaf_hash,
    });

    const CMutableTransaction tx_credit = BuildCreditingTransaction(BuildP2MROutput(merkle_root), /*nValue=*/5'000);
    CMutableTransaction tx_spend = BuildSpendingTransaction(CScript{}, CScriptWitness{}, CTransaction{tx_credit});
    PrecomputedTransactionData txdata;
    txdata.Init(tx_spend, {tx_credit.vout.at(0)}, /*force=*/true);

    FlatSigningProvider provider;
    P2MRSpendData spenddata;
    std::vector<unsigned char> ml_control{P2MR_LEAF_VERSION};
    ml_control.insert(ml_control.end(), slh_leaf_hash.begin(), slh_leaf_hash.end());
    spenddata.scripts[ml_leaf_script].insert(ml_control);
    std::vector<unsigned char> slh_control{P2MR_LEAF_VERSION};
    slh_control.insert(slh_control.end(), ml_leaf_hash.begin(), ml_leaf_hash.end());
    spenddata.scripts[slh_leaf_script].insert(slh_control);
    provider.p2mr_spends[WitnessV2P2MR{merkle_root}] = spenddata;
    provider.pq_keys[ml_key.GetPubKey()] = ml_key;
    provider.pq_keys[slh_key.GetPubKey()] = slh_key;

    MutableTransactionSignatureCreator creator(
        tx_spend, /*input_idx=*/0, tx_credit.vout.at(0).nValue, &txdata, SIGHASH_DEFAULT);
    SignatureData sigdata;
    sigdata.preferred_pq_signing_algo = PQAlgorithm::SLH_DSA_128S;
    BOOST_REQUIRE(ProduceSignature(provider, creator, tx_credit.vout.at(0).scriptPubKey, sigdata));
    BOOST_REQUIRE_EQUAL(sigdata.scriptWitness.stack.size(), 3U);
    BOOST_CHECK(sigdata.scriptWitness.stack[1] == slh_leaf_script);
    BOOST_CHECK_EQUAL(sigdata.scriptWitness.stack[0].size(), SLHDSA128S_SIGNATURE_SIZE);
}

BOOST_AUTO_TEST_CASE(psbt_multisig_p2mr_partial_combine_finalize)
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
    P2MRSignContext ctx{leaf_script};

    PartiallySignedTransaction psbt_base{ctx.tx_spend};
    psbt_base.inputs.at(0).witness_utxo = ctx.tx_credit.vout.at(0);
    const PrecomputedTransactionData txdata = PrecomputePSBTData(psbt_base);

    PartiallySignedTransaction psbt_a = psbt_base;
    const FlatSigningProvider provider_a = BuildSingleLeafProviderWithKeys(ctx.merkle_root, leaf_script, {key1});
    BOOST_CHECK(!SignPSBTInput(provider_a, psbt_a, /*index=*/0, &txdata, SIGHASH_DEFAULT, nullptr, /*finalize=*/false));
    BOOST_CHECK_EQUAL(psbt_a.inputs.at(0).m_p2mr_pq_sigs.size(), 1U);

    PartiallySignedTransaction psbt_b = psbt_base;
    const FlatSigningProvider provider_b = BuildSingleLeafProviderWithKeys(ctx.merkle_root, leaf_script, {key3});
    BOOST_CHECK(!SignPSBTInput(provider_b, psbt_b, /*index=*/0, &txdata, SIGHASH_DEFAULT, nullptr, /*finalize=*/false));
    BOOST_CHECK_EQUAL(psbt_b.inputs.at(0).m_p2mr_pq_sigs.size(), 1U);

    PartiallySignedTransaction combined;
    BOOST_REQUIRE(CombinePSBTs(combined, {psbt_a, psbt_b}));
    BOOST_CHECK_EQUAL(combined.inputs.at(0).m_p2mr_pq_sigs.size(), 2U);

    BOOST_REQUIRE(FinalizePSBT(combined));
    BOOST_REQUIRE(!combined.inputs.at(0).final_script_witness.IsNull());
    const auto& stack = combined.inputs.at(0).final_script_witness.stack;
    BOOST_REQUIRE_EQUAL(stack.size(), 5U);
    const size_t non_empty_sigs = (!stack[0].empty() ? 1U : 0U) + (!stack[1].empty() ? 1U : 0U) + (!stack[2].empty() ? 1U : 0U);
    BOOST_CHECK_EQUAL(non_empty_sigs, 2U);
    BOOST_CHECK(stack[3] == leaf_script);
    BOOST_CHECK(stack[4] == std::vector<unsigned char>{P2MR_LEAF_VERSION});
}

BOOST_AUTO_TEST_CASE(psbt_ctv_multisig_p2mr_partial_combine_finalize)
{
    CPQKey key1;
    key1.MakeNewKey(PQAlgorithm::ML_DSA_44);
    BOOST_REQUIRE(key1.IsValid());
    CPQKey key2;
    key2.MakeNewKey(PQAlgorithm::SLH_DSA_128S);
    BOOST_REQUIRE(key2.IsValid());

    const CMutableTransaction tx_credit = BuildCreditingTransaction(BuildP2MROutput(uint256::ONE), /*nValue=*/5'000);
    const CMutableTransaction tx_spend = BuildSpendingTransaction(CScript{}, CScriptWitness{}, CTransaction{tx_credit});
    PrecomputedTransactionData txdata_template;
    txdata_template.Init(tx_spend, {tx_credit.vout.at(0)}, /*force=*/true);
    const uint256 ctv_hash = ComputeCTVHash(tx_spend, /*nIn=*/0, txdata_template);
    const std::vector<unsigned char> leaf_script = BuildP2MRMultisigCTVScript(
        ctv_hash,
        /*threshold=*/2,
        {
            {PQAlgorithm::ML_DSA_44, key1.GetPubKey()},
            {PQAlgorithm::SLH_DSA_128S, key2.GetPubKey()},
        });
    P2MRSignContext ctx{leaf_script};

    PartiallySignedTransaction psbt_base{ctx.tx_spend};
    psbt_base.inputs.at(0).witness_utxo = ctx.tx_credit.vout.at(0);
    const PrecomputedTransactionData txdata = PrecomputePSBTData(psbt_base);

    PartiallySignedTransaction psbt_a = psbt_base;
    const FlatSigningProvider provider_a = BuildSingleLeafProviderWithKeys(ctx.merkle_root, leaf_script, {key1});
    BOOST_CHECK(!SignPSBTInput(provider_a, psbt_a, /*index=*/0, &txdata, SIGHASH_DEFAULT, nullptr, /*finalize=*/false));
    BOOST_CHECK_EQUAL(psbt_a.inputs.at(0).m_p2mr_pq_sigs.size(), 1U);

    PartiallySignedTransaction psbt_b = psbt_base;
    const FlatSigningProvider provider_b = BuildSingleLeafProviderWithKeys(ctx.merkle_root, leaf_script, {key2});
    BOOST_CHECK(!SignPSBTInput(provider_b, psbt_b, /*index=*/0, &txdata, SIGHASH_DEFAULT, nullptr, /*finalize=*/false));
    BOOST_CHECK_EQUAL(psbt_b.inputs.at(0).m_p2mr_pq_sigs.size(), 1U);

    PartiallySignedTransaction combined;
    BOOST_REQUIRE(CombinePSBTs(combined, {psbt_a, psbt_b}));
    BOOST_CHECK_EQUAL(combined.inputs.at(0).m_p2mr_pq_sigs.size(), 2U);

    BOOST_REQUIRE(FinalizePSBT(combined));
    BOOST_REQUIRE(!combined.inputs.at(0).final_script_witness.IsNull());
    const auto& stack = combined.inputs.at(0).final_script_witness.stack;
    BOOST_REQUIRE_EQUAL(stack.size(), 4U);
    const size_t non_empty_sigs = (!stack[0].empty() ? 1U : 0U) + (!stack[1].empty() ? 1U : 0U);
    BOOST_CHECK_EQUAL(non_empty_sigs, 2U);
    BOOST_CHECK(stack[2] == leaf_script);
    BOOST_CHECK(stack[3] == std::vector<unsigned char>{P2MR_LEAF_VERSION});
}

BOOST_AUTO_TEST_CASE(psbt_csv_multisig_p2mr_partial_combine_finalize)
{
    CPQKey key1;
    key1.MakeNewKey(PQAlgorithm::ML_DSA_44);
    BOOST_REQUIRE(key1.IsValid());
    CPQKey key2;
    key2.MakeNewKey(PQAlgorithm::SLH_DSA_128S);
    BOOST_REQUIRE(key2.IsValid());

    const std::vector<unsigned char> leaf_script = BuildP2MRCSVMultisigScript(
        /*sequence=*/144,
        /*threshold=*/2,
        {
            {PQAlgorithm::ML_DSA_44, key1.GetPubKey()},
            {PQAlgorithm::SLH_DSA_128S, key2.GetPubKey()},
        });
    P2MRSignContext ctx{leaf_script};
    ctx.tx_spend.version = 2;
    ctx.tx_spend.vin.at(0).nSequence = 144;
    ctx.txdata = PrecomputedTransactionData{};
    ctx.txdata.Init(ctx.tx_spend, {ctx.tx_credit.vout.at(0)}, /*force=*/true);

    PartiallySignedTransaction psbt_base{ctx.tx_spend};
    psbt_base.inputs.at(0).witness_utxo = ctx.tx_credit.vout.at(0);
    const PrecomputedTransactionData txdata = PrecomputePSBTData(psbt_base);

    PartiallySignedTransaction psbt_a = psbt_base;
    const FlatSigningProvider provider_a = BuildSingleLeafProviderWithKeys(ctx.merkle_root, leaf_script, {key1});
    BOOST_CHECK(!SignPSBTInput(provider_a, psbt_a, /*index=*/0, &txdata, SIGHASH_DEFAULT, nullptr, /*finalize=*/false));
    BOOST_CHECK_EQUAL(psbt_a.inputs.at(0).m_p2mr_pq_sigs.size(), 1U);

    PartiallySignedTransaction psbt_b = psbt_base;
    const FlatSigningProvider provider_b = BuildSingleLeafProviderWithKeys(ctx.merkle_root, leaf_script, {key2});
    BOOST_CHECK(!SignPSBTInput(provider_b, psbt_b, /*index=*/0, &txdata, SIGHASH_DEFAULT, nullptr, /*finalize=*/false));
    BOOST_CHECK_EQUAL(psbt_b.inputs.at(0).m_p2mr_pq_sigs.size(), 1U);

    PartiallySignedTransaction combined;
    BOOST_REQUIRE(CombinePSBTs(combined, {psbt_a, psbt_b}));
    BOOST_CHECK_EQUAL(combined.inputs.at(0).m_p2mr_pq_sigs.size(), 2U);

    BOOST_REQUIRE(FinalizePSBT(combined));
    BOOST_REQUIRE(!combined.inputs.at(0).final_script_witness.IsNull());
    const auto& stack = combined.inputs.at(0).final_script_witness.stack;
    BOOST_REQUIRE_EQUAL(stack.size(), 4U);
    const size_t non_empty_sigs = (!stack[0].empty() ? 1U : 0U) + (!stack[1].empty() ? 1U : 0U);
    BOOST_CHECK_EQUAL(non_empty_sigs, 2U);
    BOOST_CHECK(stack[2] == leaf_script);
    BOOST_CHECK(stack[3] == std::vector<unsigned char>{P2MR_LEAF_VERSION});
}

BOOST_AUTO_TEST_CASE(psbt_cltv_multisig_finalize_rejects_unsatisfied_locktime)
{
    CPQKey key1;
    key1.MakeNewKey(PQAlgorithm::ML_DSA_44);
    BOOST_REQUIRE(key1.IsValid());
    CPQKey key2;
    key2.MakeNewKey(PQAlgorithm::SLH_DSA_128S);
    BOOST_REQUIRE(key2.IsValid());

    const std::vector<unsigned char> leaf_script = BuildP2MRCLTVMultisigScript(
        /*locktime=*/700,
        /*threshold=*/1,
        {
            {PQAlgorithm::ML_DSA_44, key1.GetPubKey()},
            {PQAlgorithm::SLH_DSA_128S, key2.GetPubKey()},
        });
    P2MRSignContext ctx{leaf_script};

    PartiallySignedTransaction psbt{ctx.tx_spend};
    psbt.inputs.at(0).witness_utxo = ctx.tx_credit.vout.at(0);
    const PrecomputedTransactionData txdata = PrecomputePSBTData(psbt);

    const FlatSigningProvider provider = BuildSingleLeafProviderWithKeys(ctx.merkle_root, leaf_script, {key1});
    BOOST_CHECK(!SignPSBTInput(provider, psbt, /*index=*/0, &txdata, SIGHASH_DEFAULT, nullptr, /*finalize=*/false));
    BOOST_CHECK(!FinalizePSBT(psbt));
}

BOOST_AUTO_TEST_CASE(psbt_csv_multisig_finalize_rejects_unsatisfied_sequence)
{
    CPQKey key1;
    key1.MakeNewKey(PQAlgorithm::ML_DSA_44);
    BOOST_REQUIRE(key1.IsValid());
    CPQKey key2;
    key2.MakeNewKey(PQAlgorithm::SLH_DSA_128S);
    BOOST_REQUIRE(key2.IsValid());

    const std::vector<unsigned char> leaf_script = BuildP2MRCSVMultisigScript(
        /*sequence=*/144,
        /*threshold=*/1,
        {
            {PQAlgorithm::ML_DSA_44, key1.GetPubKey()},
            {PQAlgorithm::SLH_DSA_128S, key2.GetPubKey()},
        });
    P2MRSignContext ctx{leaf_script};

    PartiallySignedTransaction psbt{ctx.tx_spend};
    psbt.inputs.at(0).witness_utxo = ctx.tx_credit.vout.at(0);
    const PrecomputedTransactionData txdata = PrecomputePSBTData(psbt);

    const FlatSigningProvider provider = BuildSingleLeafProviderWithKeys(ctx.merkle_root, leaf_script, {key1});
    BOOST_CHECK(!SignPSBTInput(provider, psbt, /*index=*/0, &txdata, SIGHASH_DEFAULT, nullptr, /*finalize=*/false));
    BOOST_CHECK(!FinalizePSBT(psbt));
}

BOOST_AUTO_TEST_CASE(psbt_fill_signature_data_populates_p2mr_fields)
{
    PSBTInput input;
    input.m_p2mr_leaf_script = {0x51};
    input.m_p2mr_control_block = {P2MR_LEAF_VERSION};
    const uint256 leaf_hash = uint256::ONE;
    const std::vector<unsigned char> pubkey(MLDSA44_PUBKEY_SIZE, 0x01);
    input.m_p2mr_pq_sigs[std::make_pair(leaf_hash, pubkey)] = {0xAA};
    input.m_p2mr_csfs_msgs[std::make_pair(leaf_hash, pubkey)] = {0xBB};
    input.m_p2mr_csfs_sigs[std::make_pair(leaf_hash, pubkey)] = {0xCC};

    SignatureData sigdata;
    input.FillSignatureData(sigdata);
    BOOST_CHECK(sigdata.p2mr_leaf_script == input.m_p2mr_leaf_script);
    BOOST_CHECK(sigdata.p2mr_control_block == input.m_p2mr_control_block);
    BOOST_CHECK(sigdata.p2mr_script_sigs == input.m_p2mr_pq_sigs);
    BOOST_CHECK(sigdata.p2mr_csfs_msgs == input.m_p2mr_csfs_msgs);
    BOOST_CHECK(sigdata.p2mr_csfs_sigs == input.m_p2mr_csfs_sigs);
}

BOOST_AUTO_TEST_CASE(psbt_from_signature_data_writes_p2mr_fields_back)
{
    const uint256 leaf_hash = uint256::ONE;
    const std::vector<unsigned char> pubkey(MLDSA44_PUBKEY_SIZE, 0x02);
    SignatureData sigdata;
    sigdata.p2mr_leaf_script = {0x52};
    sigdata.p2mr_control_block = {P2MR_LEAF_VERSION};
    sigdata.p2mr_script_sigs[std::make_pair(leaf_hash, pubkey)] = {0xAB};
    sigdata.p2mr_csfs_msgs[std::make_pair(leaf_hash, pubkey)] = {0xBC};
    sigdata.p2mr_csfs_sigs[std::make_pair(leaf_hash, pubkey)] = {0xCD};

    PSBTInput input;
    input.FromSignatureData(sigdata);
    BOOST_CHECK(input.m_p2mr_leaf_script == sigdata.p2mr_leaf_script);
    BOOST_CHECK(input.m_p2mr_control_block == sigdata.p2mr_control_block);
    BOOST_CHECK(input.m_p2mr_pq_sigs == sigdata.p2mr_script_sigs);
    BOOST_CHECK(input.m_p2mr_csfs_msgs == sigdata.p2mr_csfs_msgs);
    BOOST_CHECK(input.m_p2mr_csfs_sigs == sigdata.p2mr_csfs_sigs);
}

BOOST_AUTO_TEST_CASE(psbt_input_roundtrips_new_p2mr_keys)
{
    PSBTInput input;
    input.m_p2mr_leaf_script = {0x51, 0x52};
    input.m_p2mr_control_block = {P2MR_LEAF_VERSION};
    input.m_p2mr_leaf_version = P2MR_LEAF_VERSION;
    const uint256 leaf_hash = uint256::ONE;
    const std::vector<unsigned char> pubkey(MLDSA44_PUBKEY_SIZE, 0x03);
    input.m_p2mr_pq_sigs[std::make_pair(leaf_hash, pubkey)] = {0x01, 0x02};
    input.m_p2mr_csfs_msgs[std::make_pair(leaf_hash, pubkey)] = {0x03};
    input.m_p2mr_csfs_sigs[std::make_pair(leaf_hash, pubkey)] = {0x04, 0x05};
    const uint256 merkle_root_two = Hash(std::vector<unsigned char>{0x02});
    input.m_p2mr_merkle_root = merkle_root_two;
    input.m_p2mr_bip32_paths[pubkey] = {0x11, 0x22, 0x33};

    DataStream ss{};
    ss << input;
    PSBTInput decoded;
    ss >> decoded;

    BOOST_CHECK(decoded.m_p2mr_leaf_script == input.m_p2mr_leaf_script);
    BOOST_CHECK(decoded.m_p2mr_control_block == input.m_p2mr_control_block);
    BOOST_CHECK(decoded.m_p2mr_pq_sigs == input.m_p2mr_pq_sigs);
    BOOST_CHECK(decoded.m_p2mr_csfs_msgs == input.m_p2mr_csfs_msgs);
    BOOST_CHECK(decoded.m_p2mr_csfs_sigs == input.m_p2mr_csfs_sigs);
    BOOST_CHECK_EQUAL(decoded.m_p2mr_merkle_root, input.m_p2mr_merkle_root);
    BOOST_CHECK(decoded.m_p2mr_bip32_paths == input.m_p2mr_bip32_paths);
}

BOOST_AUTO_TEST_CASE(psbt_input_disambiguates_same_pubkey_across_two_leaves)
{
    PSBTInput input;
    const std::vector<unsigned char> pubkey(MLDSA44_PUBKEY_SIZE, 0x0A);
    input.m_p2mr_pq_sigs[std::make_pair(uint256::ONE, pubkey)] = {0x01};
    const uint256 leaf_hash_two = Hash(std::vector<unsigned char>{0x03});
    input.m_p2mr_pq_sigs[std::make_pair(leaf_hash_two, pubkey)] = {0x02};

    DataStream ss{};
    ss << input;
    PSBTInput decoded;
    ss >> decoded;

    BOOST_CHECK_EQUAL(decoded.m_p2mr_pq_sigs.size(), 2U);
    BOOST_CHECK(decoded.m_p2mr_pq_sigs.count(std::make_pair(uint256::ONE, pubkey)));
    BOOST_CHECK(decoded.m_p2mr_pq_sigs.count(std::make_pair(leaf_hash_two, pubkey)));
}

BOOST_AUTO_TEST_CASE(combinepsbt_merges_complementary_p2mr_material)
{
    CMutableTransaction tx;
    tx.vin.resize(1);
    tx.vin[0].prevout = COutPoint{Txid::FromUint256(uint256::ONE), 0};
    tx.vout.resize(1);
    tx.vout[0].nValue = 1'000;
    tx.vout[0].scriptPubKey = CScript{} << OP_TRUE;

    PartiallySignedTransaction a{tx};
    PartiallySignedTransaction b{tx};
    a.inputs[0].m_p2mr_leaf_script = {0x51};
    a.inputs[0].m_p2mr_control_block = {P2MR_LEAF_VERSION};
    b.inputs[0].m_p2mr_leaf_script = {0x51};
    b.inputs[0].m_p2mr_control_block = {P2MR_LEAF_VERSION};

    const uint256 leaf_hash = uint256::ONE;
    const std::vector<unsigned char> pubkey(MLDSA44_PUBKEY_SIZE, 0x05);
    a.inputs[0].m_p2mr_pq_sigs[std::make_pair(leaf_hash, pubkey)] = {0x01};
    b.inputs[0].m_p2mr_csfs_msgs[std::make_pair(leaf_hash, pubkey)] = {0x02};
    b.inputs[0].m_p2mr_csfs_sigs[std::make_pair(leaf_hash, pubkey)] = {0x03};

    PartiallySignedTransaction out;
    BOOST_REQUIRE(CombinePSBTs(out, {a, b}));
    BOOST_CHECK_EQUAL(out.inputs[0].m_p2mr_pq_sigs.size(), 1U);
    BOOST_CHECK_EQUAL(out.inputs[0].m_p2mr_csfs_msgs.size(), 1U);
    BOOST_CHECK_EQUAL(out.inputs[0].m_p2mr_csfs_sigs.size(), 1U);
}

BOOST_AUTO_TEST_CASE(combinepsbt_replaces_malformed_p2mr_partial_sig_with_valid_one)
{
    CPQKey key;
    key.MakeNewKey(PQAlgorithm::ML_DSA_44);
    BOOST_REQUIRE(key.IsValid());
    const std::vector<unsigned char> leaf_script = BuildP2MRScript(PQAlgorithm::ML_DSA_44, key.GetPubKey());
    P2MRSignContext ctx{leaf_script};
    const uint256 leaf_hash = ComputeP2MRLeafHash(P2MR_LEAF_VERSION, leaf_script);

    PartiallySignedTransaction psbt_base{ctx.tx_spend};
    psbt_base.inputs.at(0).witness_utxo = ctx.tx_credit.vout.at(0);
    const PrecomputedTransactionData txdata = PrecomputePSBTData(psbt_base);

    PartiallySignedTransaction psbt_good = psbt_base;
    const FlatSigningProvider provider = BuildSingleLeafProviderWithKeys(ctx.merkle_root, leaf_script, {key});
    BOOST_REQUIRE(SignPSBTInput(provider, psbt_good, /*index=*/0, &txdata, SIGHASH_DEFAULT, nullptr, /*finalize=*/false));
    BOOST_REQUIRE_EQUAL(psbt_good.inputs.at(0).m_p2mr_pq_sigs.size(), 1U);
    const auto good_it = psbt_good.inputs.at(0).m_p2mr_pq_sigs.find(std::make_pair(leaf_hash, key.GetPubKey()));
    BOOST_REQUIRE(good_it != psbt_good.inputs.at(0).m_p2mr_pq_sigs.end());
    const std::vector<unsigned char> good_sig = good_it->second;
    BOOST_REQUIRE_EQUAL(good_sig.size(), MLDSA44_SIGNATURE_SIZE);

    PartiallySignedTransaction psbt_bad = psbt_base;
    psbt_bad.inputs.at(0).m_p2mr_pq_sigs[std::make_pair(leaf_hash, key.GetPubKey())] = {0x00};

    PartiallySignedTransaction out;
    BOOST_REQUIRE(CombinePSBTs(out, {psbt_bad, psbt_good}));
    const auto out_it = out.inputs.at(0).m_p2mr_pq_sigs.find(std::make_pair(leaf_hash, key.GetPubKey()));
    BOOST_REQUIRE(out_it != out.inputs.at(0).m_p2mr_pq_sigs.end());
    BOOST_CHECK(out_it->second == good_sig);
    BOOST_CHECK(FinalizePSBT(out));
}

BOOST_AUTO_TEST_CASE(combinepsbt_replaces_wrong_but_well_formed_p2mr_partial_sig_with_valid_one)
{
    CPQKey key;
    key.MakeNewKey(PQAlgorithm::ML_DSA_44);
    BOOST_REQUIRE(key.IsValid());
    const std::vector<unsigned char> leaf_script = BuildP2MRScript(PQAlgorithm::ML_DSA_44, key.GetPubKey());
    P2MRSignContext ctx{leaf_script};
    const uint256 leaf_hash = ComputeP2MRLeafHash(P2MR_LEAF_VERSION, leaf_script);

    PartiallySignedTransaction psbt_base{ctx.tx_spend};
    psbt_base.inputs.at(0).witness_utxo = ctx.tx_credit.vout.at(0);
    const PrecomputedTransactionData txdata = PrecomputePSBTData(psbt_base);

    PartiallySignedTransaction psbt_good = psbt_base;
    const FlatSigningProvider provider = BuildSingleLeafProviderWithKeys(ctx.merkle_root, leaf_script, {key});
    BOOST_REQUIRE(SignPSBTInput(provider, psbt_good, /*index=*/0, &txdata, SIGHASH_DEFAULT, nullptr, /*finalize=*/false));
    const auto good_key = std::make_pair(leaf_hash, key.GetPubKey());
    const auto good_it = psbt_good.inputs.at(0).m_p2mr_pq_sigs.find(good_key);
    BOOST_REQUIRE(good_it != psbt_good.inputs.at(0).m_p2mr_pq_sigs.end());
    const std::vector<unsigned char> good_sig = good_it->second;
    BOOST_REQUIRE_EQUAL(good_sig.size(), MLDSA44_SIGNATURE_SIZE);

    PartiallySignedTransaction psbt_bad = psbt_base;
    std::vector<unsigned char> wrong_sig(MLDSA44_SIGNATURE_SIZE, 0x42);
    BOOST_REQUIRE(wrong_sig != good_sig);
    psbt_bad.inputs.at(0).m_p2mr_pq_sigs[good_key] = wrong_sig;

    const auto assert_combined = [&](const std::vector<PartiallySignedTransaction>& psbts) {
        PartiallySignedTransaction out;
        BOOST_REQUIRE(CombinePSBTs(out, psbts));
        const auto out_it = out.inputs.at(0).m_p2mr_pq_sigs.find(good_key);
        BOOST_REQUIRE(out_it != out.inputs.at(0).m_p2mr_pq_sigs.end());
        BOOST_CHECK(out_it->second == good_sig);
        BOOST_CHECK(FinalizePSBT(out));
    };
    assert_combined({psbt_bad, psbt_good});
    assert_combined({psbt_good, psbt_bad});
}

BOOST_AUTO_TEST_CASE(combinepsbt_rejects_conflicting_selected_p2mr_leaf)
{
    CMutableTransaction tx;
    tx.vin.resize(1);
    tx.vin[0].prevout = COutPoint{Txid::FromUint256(uint256::ONE), 0};
    tx.vout.resize(1);
    tx.vout[0].nValue = 1'000;
    tx.vout[0].scriptPubKey = CScript{} << OP_TRUE;

    PartiallySignedTransaction a{tx};
    PartiallySignedTransaction b{tx};
    a.inputs[0].m_p2mr_leaf_script = {0x51};
    a.inputs[0].m_p2mr_control_block = {P2MR_LEAF_VERSION};
    b.inputs[0].m_p2mr_leaf_script = {0x52};
    b.inputs[0].m_p2mr_control_block = {P2MR_LEAF_VERSION, 0x01, 0x02};

    PartiallySignedTransaction out;
    BOOST_CHECK(!CombinePSBTs(out, {a, b}));
}

BOOST_AUTO_TEST_CASE(combinepsbt_rejects_conflicting_p2mr_merkle_root)
{
    CMutableTransaction tx;
    tx.vin.resize(1);
    tx.vin[0].prevout = COutPoint{Txid::FromUint256(uint256::ONE), 0};
    tx.vout.resize(1);
    tx.vout[0].nValue = 1'000;
    tx.vout[0].scriptPubKey = CScript{} << OP_TRUE;

    PartiallySignedTransaction a{tx};
    PartiallySignedTransaction b{tx};
    a.inputs[0].m_p2mr_merkle_root = Hash(std::vector<unsigned char>{0x01});
    b.inputs[0].m_p2mr_merkle_root = Hash(std::vector<unsigned char>{0x02});

    PartiallySignedTransaction out;
    BOOST_CHECK(!CombinePSBTs(out, {a, b}));
}

BOOST_AUTO_TEST_CASE(psbt_output_roundtrips_p2mr_fields)
{
    PSBTOutput output;
    output.m_p2mr_tree = {0x01, 0x02, 0x03};
    output.m_p2mr_bip32_paths[std::vector<unsigned char>(MLDSA44_PUBKEY_SIZE, 0x07)] = {0xAA, 0xBB};

    DataStream ss{};
    ss << output;
    PSBTOutput decoded;
    ss >> decoded;

    BOOST_CHECK(decoded.m_p2mr_tree == output.m_p2mr_tree);
    BOOST_CHECK(decoded.m_p2mr_bip32_paths == output.m_p2mr_bip32_paths);
}

BOOST_AUTO_TEST_CASE(psbt_input_rejects_invalid_p2mr_pubkey_sizes)
{
    {
        PSBTInput input;
        input.m_p2mr_pq_sigs[std::make_pair(uint256::ONE, std::vector<unsigned char>(33, 0x01))] = {0x01};
        DataStream ss{};
        ss << input;
        PSBTInput decoded;
        BOOST_CHECK_THROW(ss >> decoded, std::ios_base::failure);
    }

    {
        PSBTInput input;
        input.m_p2mr_bip32_paths[std::vector<unsigned char>(31, 0x02)] = {0x11, 0x22};
        DataStream ss{};
        ss << input;
        PSBTInput decoded;
        BOOST_CHECK_THROW(ss >> decoded, std::ios_base::failure);
    }

    {
        PSBTInput input;
        input.m_p2mr_csfs_msgs[std::make_pair(uint256::ONE, std::vector<unsigned char>(64, 0x03))] = {0xAA};
        DataStream ss{};
        ss << input;
        PSBTInput decoded;
        BOOST_CHECK_THROW(ss >> decoded, std::ios_base::failure);
    }

    {
        PSBTInput input;
        input.m_p2mr_csfs_sigs[std::make_pair(uint256::ONE, std::vector<unsigned char>(64, 0x04))] = {0xBB};
        DataStream ss{};
        ss << input;
        PSBTInput decoded;
        BOOST_CHECK_THROW(ss >> decoded, std::ios_base::failure);
    }
}

BOOST_AUTO_TEST_CASE(psbt_output_rejects_invalid_p2mr_pubkey_sizes)
{
    PSBTOutput output;
    output.m_p2mr_bip32_paths[std::vector<unsigned char>(48, 0x05)] = {0x99};
    DataStream ss{};
    ss << output;
    PSBTOutput decoded;
    BOOST_CHECK_THROW(ss >> decoded, std::ios_base::failure);
}

BOOST_AUTO_TEST_CASE(external_signer_matches_p2mr_bip32_fingerprint)
{
    CMutableTransaction tx;
    tx.vin.resize(1);
    tx.vin[0].prevout = COutPoint{Txid::FromUint256(uint256::ONE), 0};
    tx.vout.resize(1);
    tx.vout[0].nValue = 1'000;
    tx.vout[0].scriptPubKey = CScript{} << OP_TRUE;

    PartiallySignedTransaction psbt{tx};
    const uint256 merkle_root = ConfigureSingleLeafP2MRInput(psbt.inputs[0], {OP_TRUE});
    psbt.inputs[0].witness_utxo = CTxOut{1'000, BuildP2MROutput(merkle_root)};
    const std::vector<unsigned char> pubkey(MLDSA44_PUBKEY_SIZE, 0x23);
    psbt.inputs[0].m_p2mr_bip32_paths[pubkey] = SerializeP2MRKeyOrigin(
        /*fingerprint=*/{0x00, 0x00, 0x00, 0x01},
        /*path=*/{0x80000057, 0x80000001, 0x00000000});

    const fs::path script_path = WriteFailingMockSignerScript();
    ExternalSigner signer{
        "/bin/sh " + fs::PathToString(script_path),
        "regtest",
        "00000001",
        "mock"};

    std::string error;
    BOOST_CHECK_THROW(signer.SignTransaction(psbt, error), std::runtime_error);
    fs::remove(script_path);
}

BOOST_AUTO_TEST_CASE(external_signer_rejects_malformed_request_p2mr_bip32_origin)
{
    CMutableTransaction tx;
    tx.vin.resize(1);
    tx.vin[0].prevout = COutPoint{Txid::FromUint256(uint256::ONE), 0};
    tx.vout.resize(1);
    tx.vout[0].nValue = 1'000;
    tx.vout[0].scriptPubKey = CScript{} << OP_TRUE;

    PartiallySignedTransaction psbt{tx};
    const uint256 merkle_root = ConfigureSingleLeafP2MRInput(psbt.inputs[0], {OP_TRUE});
    psbt.inputs[0].witness_utxo = CTxOut{1'000, BuildP2MROutput(merkle_root)};
    const std::vector<unsigned char> matching_pubkey(MLDSA44_PUBKEY_SIZE, 0x24);
    psbt.inputs[0].m_p2mr_bip32_paths[matching_pubkey] = SerializeP2MRKeyOrigin(
        /*fingerprint=*/{0x00, 0x00, 0x00, 0x01},
        /*path=*/{0x80000057, 0x80000001, 0x00000000});
    const std::vector<unsigned char> malformed_pubkey(MLDSA44_PUBKEY_SIZE, 0x25);
    psbt.inputs[0].m_p2mr_bip32_paths[malformed_pubkey] = {0x01, 0x02, 0x03};

    const fs::path script_path = WriteFailingMockSignerScript();
    ExternalSigner signer{
        "/bin/sh " + fs::PathToString(script_path),
        "regtest",
        "00000001",
        "mock"};

    std::string error;
    bool ok{true};
    BOOST_CHECK_NO_THROW(ok = signer.SignTransaction(psbt, error));
    BOOST_CHECK(!ok);
    BOOST_CHECK(error.find("invalid P2MR BIP32 derivation encoding") != std::string::npos);
    fs::remove(script_path);
}

BOOST_AUTO_TEST_CASE(external_signer_rejects_invalid_p2mr_partial_sig_size)
{
    CMutableTransaction tx;
    tx.vin.resize(1);
    tx.vin[0].prevout = COutPoint{Txid::FromUint256(uint256::ONE), 0};
    tx.vout.resize(1);
    tx.vout[0].nValue = 1'000;
    tx.vout[0].scriptPubKey = CScript{} << OP_TRUE;

    PartiallySignedTransaction request_psbt{tx};
    const uint256 request_root = ConfigureSingleLeafP2MRInput(request_psbt.inputs[0], {OP_TRUE});
    request_psbt.inputs[0].witness_utxo = CTxOut{1'000, BuildP2MROutput(request_root)};
    const std::vector<unsigned char> path_pubkey(MLDSA44_PUBKEY_SIZE, 0x25);
    request_psbt.inputs[0].m_p2mr_bip32_paths[path_pubkey] = SerializeP2MRKeyOrigin(
        /*fingerprint=*/{0x00, 0x00, 0x00, 0x01},
        /*path=*/{0x80000057, 0x80000001, 0x00000000});

    PartiallySignedTransaction signer_response = request_psbt;
    const uint256 leaf_hash = ComputeP2MRLeafHash(P2MR_LEAF_VERSION, request_psbt.inputs[0].m_p2mr_leaf_script);
    signer_response.inputs[0].m_p2mr_pq_sigs[std::make_pair(leaf_hash, path_pubkey)] =
        std::vector<unsigned char>(1, 0xAA);
    const fs::path script_path = WriteStaticMockSignerScriptResponse(
        "{\"psbt\":\"" + EncodePSBTForMockSigner(signer_response) + "\"}");

    ExternalSigner signer{
        "/bin/sh " + fs::PathToString(script_path),
        "regtest",
        "00000001",
        "mock"};

    std::string error;
    BOOST_CHECK(!signer.SignTransaction(request_psbt, error));
    BOOST_CHECK(error.find("invalid P2MR partial signature") != std::string::npos);
    fs::remove(script_path);
}

BOOST_AUTO_TEST_CASE(external_signer_rejects_unexpected_p2mr_partial_sig_pubkey)
{
    CMutableTransaction tx;
    tx.vin.resize(1);
    tx.vin[0].prevout = COutPoint{Txid::FromUint256(uint256::ONE), 0};
    tx.vout.resize(1);
    tx.vout[0].nValue = 1'000;
    tx.vout[0].scriptPubKey = CScript{} << OP_TRUE;

    PartiallySignedTransaction request_psbt{tx};
    const uint256 request_root = ConfigureSingleLeafP2MRInput(request_psbt.inputs[0], {OP_TRUE});
    request_psbt.inputs[0].witness_utxo = CTxOut{1'000, BuildP2MROutput(request_root)};
    const std::vector<unsigned char> known_pubkey(MLDSA44_PUBKEY_SIZE, 0x27);
    request_psbt.inputs[0].m_p2mr_bip32_paths[known_pubkey] = SerializeP2MRKeyOrigin(
        /*fingerprint=*/{0x00, 0x00, 0x00, 0x01},
        /*path=*/{0x80000057, 0x80000001, 0x00000000});

    PartiallySignedTransaction signer_response = request_psbt;
    const std::vector<unsigned char> injected_pubkey(MLDSA44_PUBKEY_SIZE, 0x28);
    const uint256 leaf_hash = ComputeP2MRLeafHash(P2MR_LEAF_VERSION, request_psbt.inputs[0].m_p2mr_leaf_script);
    signer_response.inputs[0].m_p2mr_pq_sigs[std::make_pair(leaf_hash, injected_pubkey)] =
        std::vector<unsigned char>(MLDSA44_SIGNATURE_SIZE, 0x11);
    const fs::path script_path = WriteStaticMockSignerScriptResponse(
        "{\"psbt\":\"" + EncodePSBTForMockSigner(signer_response) + "\"}");

    ExternalSigner signer{
        "/bin/sh " + fs::PathToString(script_path),
        "regtest",
        "00000001",
        "mock"};

    std::string error;
    BOOST_CHECK(!signer.SignTransaction(request_psbt, error));
    BOOST_CHECK(error.find("unexpected P2MR partial signature pubkey") != std::string::npos);
    fs::remove(script_path);
}

BOOST_AUTO_TEST_CASE(external_signer_rejects_partial_sig_pubkey_with_nonmatching_fingerprint)
{
    CMutableTransaction tx;
    tx.vin.resize(1);
    tx.vin[0].prevout = COutPoint{Txid::FromUint256(uint256::ONE), 0};
    tx.vout.resize(1);
    tx.vout[0].nValue = 1'000;
    tx.vout[0].scriptPubKey = CScript{} << OP_TRUE;

    PartiallySignedTransaction request_psbt{tx};
    const uint256 request_root = ConfigureSingleLeafP2MRInput(request_psbt.inputs[0], {OP_TRUE});
    request_psbt.inputs[0].witness_utxo = CTxOut{1'000, BuildP2MROutput(request_root)};
    const std::vector<unsigned char> owned_pubkey(MLDSA44_PUBKEY_SIZE, 0x91);
    request_psbt.inputs[0].m_p2mr_bip32_paths[owned_pubkey] = SerializeP2MRKeyOrigin(
        /*fingerprint=*/{0x00, 0x00, 0x00, 0x01},
        /*path=*/{0x80000057, 0x80000001, 0x00000000});
    const std::vector<unsigned char> foreign_pubkey(MLDSA44_PUBKEY_SIZE, 0x92);
    request_psbt.inputs[0].m_p2mr_bip32_paths[foreign_pubkey] = SerializeP2MRKeyOrigin(
        /*fingerprint=*/{0x00, 0x00, 0x00, 0x02},
        /*path=*/{0x80000057, 0x80000001, 0x00000001});

    PartiallySignedTransaction signer_response = request_psbt;
    const uint256 leaf_hash = ComputeP2MRLeafHash(P2MR_LEAF_VERSION, request_psbt.inputs[0].m_p2mr_leaf_script);
    signer_response.inputs[0].m_p2mr_pq_sigs[std::make_pair(leaf_hash, foreign_pubkey)] =
        std::vector<unsigned char>(MLDSA44_SIGNATURE_SIZE, 0x11);
    const fs::path script_path = WriteStaticMockSignerScriptResponse(
        "{\"psbt\":\"" + EncodePSBTForMockSigner(signer_response) + "\"}");

    ExternalSigner signer{
        "/bin/sh " + fs::PathToString(script_path),
        "regtest",
        "00000001",
        "mock"};

    std::string error;
    BOOST_CHECK(!signer.SignTransaction(request_psbt, error));
    BOOST_CHECK(error.find("non-matching fingerprint") != std::string::npos);
    fs::remove(script_path);
}

BOOST_AUTO_TEST_CASE(external_signer_rejects_p2mr_partial_sig_for_unselected_leaf_hash)
{
    CMutableTransaction tx;
    tx.vin.resize(1);
    tx.vin[0].prevout = COutPoint{Txid::FromUint256(uint256::ONE), 0};
    tx.vout.resize(1);
    tx.vout[0].nValue = 1'000;
    tx.vout[0].scriptPubKey = CScript{} << OP_TRUE;

    PartiallySignedTransaction request_psbt{tx};
    const uint256 request_root = ConfigureSingleLeafP2MRInput(request_psbt.inputs[0], {OP_TRUE});
    request_psbt.inputs[0].witness_utxo = CTxOut{1'000, BuildP2MROutput(request_root)};
    const std::vector<unsigned char> path_pubkey(MLDSA44_PUBKEY_SIZE, 0x2B);
    request_psbt.inputs[0].m_p2mr_bip32_paths[path_pubkey] = SerializeP2MRKeyOrigin(
        /*fingerprint=*/{0x00, 0x00, 0x00, 0x01},
        /*path=*/{0x80000057, 0x80000001, 0x00000000});

    PartiallySignedTransaction signer_response = request_psbt;
    const std::vector<unsigned char> sig_pubkey(MLDSA44_PUBKEY_SIZE, 0x2C);
    const uint256 wrong_leaf_hash = ComputeP2MRLeafHash(P2MR_LEAF_VERSION, std::vector<unsigned char>{OP_FALSE});
    signer_response.inputs[0].m_p2mr_pq_sigs[std::make_pair(wrong_leaf_hash, sig_pubkey)] =
        std::vector<unsigned char>(MLDSA44_SIGNATURE_SIZE, 0x11);
    const fs::path script_path = WriteStaticMockSignerScriptResponse(
        "{\"psbt\":\"" + EncodePSBTForMockSigner(signer_response) + "\"}");

    ExternalSigner signer{
        "/bin/sh " + fs::PathToString(script_path),
        "regtest",
        "00000001",
        "mock"};

    std::string error;
    BOOST_CHECK(!signer.SignTransaction(request_psbt, error));
    BOOST_CHECK(error.find("unexpected P2MR leaf hash") != std::string::npos);
    fs::remove(script_path);
}

BOOST_AUTO_TEST_CASE(external_signer_rejects_wrong_leaf_sig_when_signer_omits_leaf_metadata)
{
    CMutableTransaction tx;
    tx.vin.resize(1);
    tx.vin[0].prevout = COutPoint{Txid::FromUint256(uint256::ONE), 0};
    tx.vout.resize(1);
    tx.vout[0].nValue = 1'000;
    tx.vout[0].scriptPubKey = CScript{} << OP_TRUE;

    PartiallySignedTransaction request_psbt{tx};
    const uint256 request_root = ConfigureSingleLeafP2MRInput(request_psbt.inputs[0], {OP_TRUE});
    request_psbt.inputs[0].witness_utxo = CTxOut{1'000, BuildP2MROutput(request_root)};
    const std::vector<unsigned char> path_pubkey(MLDSA44_PUBKEY_SIZE, 0x2F);
    request_psbt.inputs[0].m_p2mr_bip32_paths[path_pubkey] = SerializeP2MRKeyOrigin(
        /*fingerprint=*/{0x00, 0x00, 0x00, 0x01},
        /*path=*/{0x80000057, 0x80000001, 0x00000000});

    PartiallySignedTransaction signer_response = request_psbt;
    signer_response.inputs[0].m_p2mr_leaf_script.clear();
    signer_response.inputs[0].m_p2mr_control_block.clear();
    const std::vector<unsigned char> sig_pubkey(MLDSA44_PUBKEY_SIZE, 0x30);
    const uint256 wrong_leaf_hash = ComputeP2MRLeafHash(P2MR_LEAF_VERSION, std::vector<unsigned char>{OP_FALSE});
    signer_response.inputs[0].m_p2mr_pq_sigs[std::make_pair(wrong_leaf_hash, sig_pubkey)] =
        std::vector<unsigned char>(MLDSA44_SIGNATURE_SIZE, 0x33);
    const fs::path script_path = WriteStaticMockSignerScriptResponse(
        "{\"psbt\":\"" + EncodePSBTForMockSigner(signer_response) + "\"}");

    ExternalSigner signer{
        "/bin/sh " + fs::PathToString(script_path),
        "regtest",
        "00000001",
        "mock"};

    std::string error;
    BOOST_CHECK(!signer.SignTransaction(request_psbt, error));
    BOOST_CHECK(error.find("unexpected P2MR leaf hash") != std::string::npos);
    fs::remove(script_path);
}

BOOST_AUTO_TEST_CASE(external_signer_rejects_conflicting_selected_leaf_metadata)
{
    CMutableTransaction tx;
    tx.vin.resize(1);
    tx.vin[0].prevout = COutPoint{Txid::FromUint256(uint256::ONE), 0};
    tx.vout.resize(1);
    tx.vout[0].nValue = 1'000;
    tx.vout[0].scriptPubKey = CScript{} << OP_TRUE;

    PartiallySignedTransaction request_psbt{tx};
    const uint256 request_root = ConfigureSingleLeafP2MRInput(request_psbt.inputs[0], {OP_TRUE});
    request_psbt.inputs[0].witness_utxo = CTxOut{1'000, BuildP2MROutput(request_root)};
    const std::vector<unsigned char> path_pubkey(MLDSA44_PUBKEY_SIZE, 0x31);
    request_psbt.inputs[0].m_p2mr_bip32_paths[path_pubkey] = SerializeP2MRKeyOrigin(
        /*fingerprint=*/{0x00, 0x00, 0x00, 0x01},
        /*path=*/{0x80000057, 0x80000001, 0x00000000});

    PartiallySignedTransaction signer_response = request_psbt;
    signer_response.inputs[0].m_p2mr_leaf_script = {OP_FALSE};
    const fs::path script_path = WriteStaticMockSignerScriptResponse(
        "{\"psbt\":\"" + EncodePSBTForMockSigner(signer_response) + "\"}");

    ExternalSigner signer{
        "/bin/sh " + fs::PathToString(script_path),
        "regtest",
        "00000001",
        "mock"};

    std::string error;
    BOOST_CHECK(!signer.SignTransaction(request_psbt, error));
    BOOST_CHECK(error.find("conflicting selected P2MR leaf") != std::string::npos);
    fs::remove(script_path);
}

BOOST_AUTO_TEST_CASE(external_signer_rejects_unsupported_selected_leaf_version)
{
    CMutableTransaction tx;
    tx.vin.resize(1);
    tx.vin[0].prevout = COutPoint{Txid::FromUint256(uint256::ONE), 0};
    tx.vout.resize(1);
    tx.vout[0].nValue = 1'000;
    tx.vout[0].scriptPubKey = CScript{} << OP_TRUE;

    PartiallySignedTransaction request_psbt{tx};
    const uint256 request_root = ConfigureSingleLeafP2MRInput(request_psbt.inputs[0], {OP_TRUE});
    request_psbt.inputs[0].witness_utxo = CTxOut{1'000, BuildP2MROutput(request_root)};
    const std::vector<unsigned char> path_pubkey(MLDSA44_PUBKEY_SIZE, 0x32);
    request_psbt.inputs[0].m_p2mr_bip32_paths[path_pubkey] = SerializeP2MRKeyOrigin(
        /*fingerprint=*/{0x00, 0x00, 0x00, 0x01},
        /*path=*/{0x80000057, 0x80000001, 0x00000000});

    PartiallySignedTransaction signer_response = request_psbt;
    signer_response.inputs[0].m_p2mr_leaf_version = static_cast<uint8_t>(P2MR_LEAF_VERSION - 1);
    const fs::path script_path = WriteStaticMockSignerScriptResponse(
        "{\"psbt\":\"" + EncodePSBTForMockSigner(signer_response) + "\"}");

    ExternalSigner signer{
        "/bin/sh " + fs::PathToString(script_path),
        "regtest",
        "00000001",
        "mock"};

    std::string error;
    BOOST_CHECK(!signer.SignTransaction(request_psbt, error));
    BOOST_CHECK(error.find("unsupported P2MR leaf version") != std::string::npos);
    fs::remove(script_path);
}

BOOST_AUTO_TEST_CASE(external_signer_rejects_unexpected_p2mr_bip32_derivation)
{
    CMutableTransaction tx;
    tx.vin.resize(1);
    tx.vin[0].prevout = COutPoint{Txid::FromUint256(uint256::ONE), 0};
    tx.vout.resize(1);
    tx.vout[0].nValue = 1'000;
    tx.vout[0].scriptPubKey = CScript{} << OP_TRUE;

    PartiallySignedTransaction request_psbt{tx};
    const uint256 request_root = ConfigureSingleLeafP2MRInput(request_psbt.inputs[0], {OP_TRUE});
    request_psbt.inputs[0].witness_utxo = CTxOut{1'000, BuildP2MROutput(request_root)};

    const std::vector<unsigned char> known_pubkey(MLDSA44_PUBKEY_SIZE, 0x33);
    request_psbt.inputs[0].m_p2mr_bip32_paths[known_pubkey] = SerializeP2MRKeyOrigin(
        /*fingerprint=*/{0x00, 0x00, 0x00, 0x01},
        /*path=*/{0x80000057, 0x80000001, 0x00000000});

    PartiallySignedTransaction signer_response = request_psbt;
    const std::vector<unsigned char> injected_pubkey(MLDSA44_PUBKEY_SIZE, 0x34);
    signer_response.inputs[0].m_p2mr_bip32_paths[injected_pubkey] = SerializeP2MRKeyOrigin(
        /*fingerprint=*/{0x00, 0x00, 0x00, 0x01},
        /*path=*/{0x80000057, 0x80000001, 0x00000009});
    const fs::path script_path = WriteStaticMockSignerScriptResponse(
        "{\"psbt\":\"" + EncodePSBTForMockSigner(signer_response) + "\"}");

    ExternalSigner signer{
        "/bin/sh " + fs::PathToString(script_path),
        "regtest",
        "00000001",
        "mock"};

    std::string error;
    BOOST_CHECK(!signer.SignTransaction(request_psbt, error));
    BOOST_CHECK(error.find("unexpected P2MR BIP32 derivation") != std::string::npos);
    fs::remove(script_path);
}

BOOST_AUTO_TEST_CASE(external_signer_rejects_conflicting_p2mr_bip32_derivation)
{
    CMutableTransaction tx;
    tx.vin.resize(1);
    tx.vin[0].prevout = COutPoint{Txid::FromUint256(uint256::ONE), 0};
    tx.vout.resize(1);
    tx.vout[0].nValue = 1'000;
    tx.vout[0].scriptPubKey = CScript{} << OP_TRUE;

    PartiallySignedTransaction request_psbt{tx};
    const uint256 request_root = ConfigureSingleLeafP2MRInput(request_psbt.inputs[0], {OP_TRUE});
    request_psbt.inputs[0].witness_utxo = CTxOut{1'000, BuildP2MROutput(request_root)};

    const std::vector<unsigned char> known_pubkey(MLDSA44_PUBKEY_SIZE, 0x35);
    request_psbt.inputs[0].m_p2mr_bip32_paths[known_pubkey] = SerializeP2MRKeyOrigin(
        /*fingerprint=*/{0x00, 0x00, 0x00, 0x01},
        /*path=*/{0x80000057, 0x80000001, 0x00000000});

    PartiallySignedTransaction signer_response = request_psbt;
    signer_response.inputs[0].m_p2mr_bip32_paths[known_pubkey] = SerializeP2MRKeyOrigin(
        /*fingerprint=*/{0x00, 0x00, 0x00, 0x01},
        /*path=*/{0x80000057, 0x80000001, 0x0000000A});
    const fs::path script_path = WriteStaticMockSignerScriptResponse(
        "{\"psbt\":\"" + EncodePSBTForMockSigner(signer_response) + "\"}");

    ExternalSigner signer{
        "/bin/sh " + fs::PathToString(script_path),
        "regtest",
        "00000001",
        "mock"};

    std::string error;
    BOOST_CHECK(!signer.SignTransaction(request_psbt, error));
    BOOST_CHECK(error.find("conflicting P2MR BIP32 derivation") != std::string::npos);
    fs::remove(script_path);
}

BOOST_AUTO_TEST_CASE(external_signer_rejects_unexpected_p2mr_csfs_message)
{
    CMutableTransaction tx;
    tx.vin.resize(1);
    tx.vin[0].prevout = COutPoint{Txid::FromUint256(uint256::ONE), 0};
    tx.vout.resize(1);
    tx.vout[0].nValue = 1'000;
    tx.vout[0].scriptPubKey = CScript{} << OP_TRUE;

    PartiallySignedTransaction request_psbt{tx};
    const uint256 request_root = ConfigureSingleLeafP2MRInput(request_psbt.inputs[0], {OP_TRUE});
    request_psbt.inputs[0].witness_utxo = CTxOut{1'000, BuildP2MROutput(request_root)};

    const std::vector<unsigned char> path_pubkey(MLDSA44_PUBKEY_SIZE, 0x39);
    request_psbt.inputs[0].m_p2mr_bip32_paths[path_pubkey] = SerializeP2MRKeyOrigin(
        /*fingerprint=*/{0x00, 0x00, 0x00, 0x01},
        /*path=*/{0x80000057, 0x80000001, 0x00000000});

    PartiallySignedTransaction signer_response = request_psbt;
    const uint256 leaf_hash = ComputeP2MRLeafHash(P2MR_LEAF_VERSION, request_psbt.inputs[0].m_p2mr_leaf_script);
    const std::vector<unsigned char> csfs_pubkey(MLDSA44_PUBKEY_SIZE, 0x3A);
    const std::pair<uint256, std::vector<unsigned char>> leaf_pubkey{leaf_hash, csfs_pubkey};
    signer_response.inputs[0].m_p2mr_csfs_msgs[leaf_pubkey] = {0xAA, 0xBB, 0xCC};
    signer_response.inputs[0].m_p2mr_csfs_sigs[leaf_pubkey] = std::vector<unsigned char>(MLDSA44_SIGNATURE_SIZE, 0x11);

    const fs::path script_path = WriteStaticMockSignerScriptResponse(
        "{\"psbt\":\"" + EncodePSBTForMockSigner(signer_response) + "\"}");
    ExternalSigner signer{
        "/bin/sh " + fs::PathToString(script_path),
        "regtest",
        "00000001",
        "mock"};

    std::string error;
    BOOST_CHECK(!signer.SignTransaction(request_psbt, error));
    BOOST_CHECK(error.find("unexpected P2MR CSFS message") != std::string::npos);
    fs::remove(script_path);
}

BOOST_AUTO_TEST_CASE(external_signer_rejects_conflicting_p2mr_csfs_message)
{
    CMutableTransaction tx;
    tx.vin.resize(1);
    tx.vin[0].prevout = COutPoint{Txid::FromUint256(uint256::ONE), 0};
    tx.vout.resize(1);
    tx.vout[0].nValue = 1'000;
    tx.vout[0].scriptPubKey = CScript{} << OP_TRUE;

    PartiallySignedTransaction request_psbt{tx};
    const uint256 request_root = ConfigureSingleLeafP2MRInput(request_psbt.inputs[0], {OP_TRUE});
    request_psbt.inputs[0].witness_utxo = CTxOut{1'000, BuildP2MROutput(request_root)};

    const std::vector<unsigned char> path_pubkey(MLDSA44_PUBKEY_SIZE, 0x3B);
    request_psbt.inputs[0].m_p2mr_bip32_paths[path_pubkey] = SerializeP2MRKeyOrigin(
        /*fingerprint=*/{0x00, 0x00, 0x00, 0x01},
        /*path=*/{0x80000057, 0x80000001, 0x00000000});

    const uint256 leaf_hash = ComputeP2MRLeafHash(P2MR_LEAF_VERSION, request_psbt.inputs[0].m_p2mr_leaf_script);
    const std::vector<unsigned char> csfs_pubkey(MLDSA44_PUBKEY_SIZE, 0x3C);
    const std::pair<uint256, std::vector<unsigned char>> leaf_pubkey{leaf_hash, csfs_pubkey};
    request_psbt.inputs[0].m_p2mr_csfs_msgs[leaf_pubkey] = {0x01, 0x02, 0x03};

    PartiallySignedTransaction signer_response = request_psbt;
    signer_response.inputs[0].m_p2mr_csfs_msgs[leaf_pubkey] = {0x04, 0x05, 0x06};
    signer_response.inputs[0].m_p2mr_csfs_sigs[leaf_pubkey] = std::vector<unsigned char>(MLDSA44_SIGNATURE_SIZE, 0x22);

    const fs::path script_path = WriteStaticMockSignerScriptResponse(
        "{\"psbt\":\"" + EncodePSBTForMockSigner(signer_response) + "\"}");
    ExternalSigner signer{
        "/bin/sh " + fs::PathToString(script_path),
        "regtest",
        "00000001",
        "mock"};

    std::string error;
    BOOST_CHECK(!signer.SignTransaction(request_psbt, error));
    BOOST_CHECK(error.find("conflicting P2MR CSFS message") != std::string::npos);
    fs::remove(script_path);
}

BOOST_AUTO_TEST_CASE(external_signer_rejects_invalid_p2mr_csfs_sig_size)
{
    CMutableTransaction tx;
    tx.vin.resize(1);
    tx.vin[0].prevout = COutPoint{Txid::FromUint256(uint256::ONE), 0};
    tx.vout.resize(1);
    tx.vout[0].nValue = 1'000;
    tx.vout[0].scriptPubKey = CScript{} << OP_TRUE;

    PartiallySignedTransaction request_psbt{tx};
    const uint256 request_root = ConfigureSingleLeafP2MRInput(request_psbt.inputs[0], {OP_TRUE});
    request_psbt.inputs[0].witness_utxo = CTxOut{1'000, BuildP2MROutput(request_root)};
    const std::vector<unsigned char> path_pubkey(MLDSA44_PUBKEY_SIZE, 0x27);
    request_psbt.inputs[0].m_p2mr_bip32_paths[path_pubkey] = SerializeP2MRKeyOrigin(
        /*fingerprint=*/{0x00, 0x00, 0x00, 0x01},
        /*path=*/{0x80000057, 0x80000001, 0x00000000});
    const std::vector<unsigned char> csfs_pubkey(SLHDSA128S_PUBKEY_SIZE, 0x28);
    request_psbt.inputs[0].m_p2mr_bip32_paths[csfs_pubkey] = SerializeP2MRKeyOrigin(
        /*fingerprint=*/{0x00, 0x00, 0x00, 0x01},
        /*path=*/{0x80000057, 0x80000001, 0x00000002});

    PartiallySignedTransaction signer_response = request_psbt;
    const uint256 leaf_hash = ComputeP2MRLeafHash(P2MR_LEAF_VERSION, request_psbt.inputs[0].m_p2mr_leaf_script);
    signer_response.inputs[0].m_p2mr_csfs_sigs[std::make_pair(leaf_hash, csfs_pubkey)] =
        std::vector<unsigned char>(1, 0xBB);
    const fs::path script_path = WriteStaticMockSignerScriptResponse(
        "{\"psbt\":\"" + EncodePSBTForMockSigner(signer_response) + "\"}");

    ExternalSigner signer{
        "/bin/sh " + fs::PathToString(script_path),
        "regtest",
        "00000001",
        "mock"};

    std::string error;
    BOOST_CHECK(!signer.SignTransaction(request_psbt, error));
    BOOST_CHECK(error.find("invalid P2MR CSFS signature") != std::string::npos);
    fs::remove(script_path);
}

BOOST_AUTO_TEST_CASE(external_signer_rejects_p2mr_csfs_signature_without_message)
{
    CMutableTransaction tx;
    tx.vin.resize(1);
    tx.vin[0].prevout = COutPoint{Txid::FromUint256(uint256::ONE), 0};
    tx.vout.resize(1);
    tx.vout[0].nValue = 1'000;
    tx.vout[0].scriptPubKey = CScript{} << OP_TRUE;

    PartiallySignedTransaction request_psbt{tx};
    const uint256 request_root = ConfigureSingleLeafP2MRInput(request_psbt.inputs[0], {OP_TRUE});
    request_psbt.inputs[0].witness_utxo = CTxOut{1'000, BuildP2MROutput(request_root)};
    const std::vector<unsigned char> path_pubkey(MLDSA44_PUBKEY_SIZE, 0x2D);
    request_psbt.inputs[0].m_p2mr_bip32_paths[path_pubkey] = SerializeP2MRKeyOrigin(
        /*fingerprint=*/{0x00, 0x00, 0x00, 0x01},
        /*path=*/{0x80000057, 0x80000001, 0x00000000});
    const std::vector<unsigned char> csfs_pubkey(SLHDSA128S_PUBKEY_SIZE, 0x2E);
    request_psbt.inputs[0].m_p2mr_bip32_paths[csfs_pubkey] = SerializeP2MRKeyOrigin(
        /*fingerprint=*/{0x00, 0x00, 0x00, 0x01},
        /*path=*/{0x80000057, 0x80000001, 0x00000002});

    const uint256 leaf_hash = ComputeP2MRLeafHash(P2MR_LEAF_VERSION, request_psbt.inputs[0].m_p2mr_leaf_script);
    PartiallySignedTransaction signer_response = request_psbt;
    signer_response.inputs[0].m_p2mr_csfs_sigs[std::make_pair(leaf_hash, csfs_pubkey)] =
        std::vector<unsigned char>(SLHDSA128S_SIGNATURE_SIZE, 0x22);
    const fs::path script_path = WriteStaticMockSignerScriptResponse(
        "{\"psbt\":\"" + EncodePSBTForMockSigner(signer_response) + "\"}");

    ExternalSigner signer{
        "/bin/sh " + fs::PathToString(script_path),
        "regtest",
        "00000001",
        "mock"};

    std::string error;
    BOOST_CHECK(!signer.SignTransaction(request_psbt, error));
    BOOST_CHECK(error.find("missing P2MR CSFS message") != std::string::npos);
    fs::remove(script_path);
}

BOOST_AUTO_TEST_CASE(external_signer_rejects_unexpected_p2mr_csfs_signature_pubkey)
{
    CMutableTransaction tx;
    tx.vin.resize(1);
    tx.vin[0].prevout = COutPoint{Txid::FromUint256(uint256::ONE), 0};
    tx.vout.resize(1);
    tx.vout[0].nValue = 1'000;
    tx.vout[0].scriptPubKey = CScript{} << OP_TRUE;

    PartiallySignedTransaction request_psbt{tx};
    const uint256 request_root = ConfigureSingleLeafP2MRInput(request_psbt.inputs[0], {OP_TRUE});
    request_psbt.inputs[0].witness_utxo = CTxOut{1'000, BuildP2MROutput(request_root)};

    const std::vector<unsigned char> signer_path_pubkey(MLDSA44_PUBKEY_SIZE, 0x6D);
    request_psbt.inputs[0].m_p2mr_bip32_paths[signer_path_pubkey] = SerializeP2MRKeyOrigin(
        /*fingerprint=*/{0x00, 0x00, 0x00, 0x01},
        /*path=*/{0x80000057, 0x80000001, 0x00000000});

    const uint256 leaf_hash = ComputeP2MRLeafHash(P2MR_LEAF_VERSION, request_psbt.inputs[0].m_p2mr_leaf_script);
    const std::vector<unsigned char> csfs_pubkey(MLDSA44_PUBKEY_SIZE, 0x6E);
    const std::pair<uint256, std::vector<unsigned char>> csfs_leaf_pubkey{leaf_hash, csfs_pubkey};
    request_psbt.inputs[0].m_p2mr_csfs_msgs[csfs_leaf_pubkey] = {0xAA, 0xBB};

    PartiallySignedTransaction signer_response = request_psbt;
    signer_response.inputs[0].m_p2mr_csfs_sigs[csfs_leaf_pubkey] =
        std::vector<unsigned char>(MLDSA44_SIGNATURE_SIZE, 0x2A);

    const fs::path script_path = WriteStaticMockSignerScriptResponse(
        "{\"psbt\":\"" + EncodePSBTForMockSigner(signer_response) + "\"}");

    ExternalSigner signer{
        "/bin/sh " + fs::PathToString(script_path),
        "regtest",
        "00000001",
        "mock"};

    std::string error;
    BOOST_CHECK(!signer.SignTransaction(request_psbt, error));
    BOOST_CHECK(error.find("unexpected P2MR CSFS signature pubkey") != std::string::npos);
    fs::remove(script_path);
}

BOOST_AUTO_TEST_CASE(external_signer_rejects_nonmatching_fingerprint_p2mr_csfs_signature_pubkey)
{
    CMutableTransaction tx;
    tx.vin.resize(1);
    tx.vin[0].prevout = COutPoint{Txid::FromUint256(uint256::ONE), 0};
    tx.vout.resize(1);
    tx.vout[0].nValue = 1'000;
    tx.vout[0].scriptPubKey = CScript{} << OP_TRUE;

    PartiallySignedTransaction request_psbt{tx};
    const uint256 request_root = ConfigureSingleLeafP2MRInput(request_psbt.inputs[0], {OP_TRUE});
    request_psbt.inputs[0].witness_utxo = CTxOut{1'000, BuildP2MROutput(request_root)};

    const uint256 leaf_hash = ComputeP2MRLeafHash(P2MR_LEAF_VERSION, request_psbt.inputs[0].m_p2mr_leaf_script);
    const std::vector<unsigned char> signer_path_pubkey(MLDSA44_PUBKEY_SIZE, 0x6F);
    request_psbt.inputs[0].m_p2mr_bip32_paths[signer_path_pubkey] = SerializeP2MRKeyOrigin(
        /*fingerprint=*/{0x00, 0x00, 0x00, 0x01},
        /*path=*/{0x80000057, 0x80000001, 0x00000001});
    const std::vector<unsigned char> csfs_pubkey(MLDSA44_PUBKEY_SIZE, 0x70);
    const std::pair<uint256, std::vector<unsigned char>> csfs_leaf_pubkey{leaf_hash, csfs_pubkey};
    request_psbt.inputs[0].m_p2mr_bip32_paths[csfs_pubkey] = SerializeP2MRKeyOrigin(
        /*fingerprint=*/{0x00, 0x00, 0x00, 0x02},
        /*path=*/{0x80000057, 0x80000001, 0x00000000});
    request_psbt.inputs[0].m_p2mr_csfs_msgs[csfs_leaf_pubkey] = {0xCC};

    PartiallySignedTransaction signer_response = request_psbt;
    signer_response.inputs[0].m_p2mr_csfs_sigs[csfs_leaf_pubkey] =
        std::vector<unsigned char>(MLDSA44_SIGNATURE_SIZE, 0x2B);

    const fs::path script_path = WriteStaticMockSignerScriptResponse(
        "{\"psbt\":\"" + EncodePSBTForMockSigner(signer_response) + "\"}");

    ExternalSigner signer{
        "/bin/sh " + fs::PathToString(script_path),
        "regtest",
        "00000001",
        "mock"};

    std::string error;
    BOOST_CHECK(!signer.SignTransaction(request_psbt, error));
    BOOST_CHECK(error.find("non-matching fingerprint") != std::string::npos);
    fs::remove(script_path);
}

BOOST_AUTO_TEST_CASE(external_signer_rejects_p2mr_input_missing_required_metadata)
{
    CMutableTransaction tx;
    tx.vin.resize(1);
    tx.vin[0].prevout = COutPoint{Txid::FromUint256(uint256::ONE), 0};
    tx.vout.resize(1);
    tx.vout[0].nValue = 1'000;
    tx.vout[0].scriptPubKey = CScript{} << OP_TRUE;

    PartiallySignedTransaction request_psbt{tx};
    request_psbt.inputs[0].witness_utxo = CTxOut{1'000, BuildP2MROutput(uint256::ONE)};
    const std::vector<unsigned char> path_pubkey(MLDSA44_PUBKEY_SIZE, 0x29);
    request_psbt.inputs[0].m_p2mr_bip32_paths[path_pubkey] = SerializeP2MRKeyOrigin(
        /*fingerprint=*/{0x00, 0x00, 0x00, 0x01},
        /*path=*/{0x80000057, 0x80000001, 0x00000000});

    ExternalSigner signer{
        "false",
        "regtest",
        "00000001",
        "mock"};

    std::string error;
    bool signed_ok = true;
    BOOST_CHECK_NO_THROW(signed_ok = signer.SignTransaction(request_psbt, error));
    BOOST_CHECK(!signed_ok);
    BOOST_CHECK(error.find("missing required P2MR metadata") != std::string::npos);
}

BOOST_AUTO_TEST_CASE(external_signer_rejects_request_p2mr_metadata_without_prevout_script)
{
    CMutableTransaction tx;
    tx.vin.resize(1);
    tx.vin[0].prevout = COutPoint{Txid::FromUint256(uint256::ONE), 0};
    tx.vout.resize(1);
    tx.vout[0].nValue = 1'000;
    tx.vout[0].scriptPubKey = CScript{} << OP_TRUE;

    PartiallySignedTransaction request_psbt{tx};
    request_psbt.inputs[0].m_p2mr_leaf_script = {OP_TRUE};
    request_psbt.inputs[0].m_p2mr_control_block = {P2MR_LEAF_VERSION};
    request_psbt.inputs[0].m_p2mr_leaf_version = P2MR_LEAF_VERSION;
    request_psbt.inputs[0].m_p2mr_merkle_root = uint256::ONE;
    const std::vector<unsigned char> path_pubkey(MLDSA44_PUBKEY_SIZE, 0x67);
    request_psbt.inputs[0].m_p2mr_bip32_paths[path_pubkey] = SerializeP2MRKeyOrigin(
        /*fingerprint=*/{0x00, 0x00, 0x00, 0x01},
        /*path=*/{0x80000057, 0x80000001, 0x00000000});

    const fs::path script_path = WriteFailingMockSignerScript();
    ExternalSigner signer{
        "/bin/sh " + fs::PathToString(script_path),
        "regtest",
        "00000001",
        "mock"};

    std::string error;
    bool signed_ok = true;
    BOOST_CHECK_NO_THROW(signed_ok = signer.SignTransaction(request_psbt, error));
    BOOST_CHECK(!signed_ok);
    BOOST_CHECK(error.find("missing prevout script for P2MR metadata") != std::string::npos);
    fs::remove(script_path);
}

BOOST_AUTO_TEST_CASE(external_signer_rejects_request_p2mr_metadata_for_non_p2mr_prevout)
{
    CMutableTransaction tx;
    tx.vin.resize(1);
    tx.vin[0].prevout = COutPoint{Txid::FromUint256(uint256::ONE), 0};
    tx.vout.resize(1);
    tx.vout[0].nValue = 1'000;
    tx.vout[0].scriptPubKey = CScript{} << OP_TRUE;

    PartiallySignedTransaction request_psbt{tx};
    request_psbt.inputs[0].witness_utxo = CTxOut{1'000, CScript{} << OP_TRUE};
    request_psbt.inputs[0].m_p2mr_leaf_script = {OP_TRUE};
    request_psbt.inputs[0].m_p2mr_control_block = {P2MR_LEAF_VERSION};
    request_psbt.inputs[0].m_p2mr_leaf_version = P2MR_LEAF_VERSION;
    request_psbt.inputs[0].m_p2mr_merkle_root = uint256::ONE;
    const std::vector<unsigned char> path_pubkey(MLDSA44_PUBKEY_SIZE, 0x68);
    request_psbt.inputs[0].m_p2mr_bip32_paths[path_pubkey] = SerializeP2MRKeyOrigin(
        /*fingerprint=*/{0x00, 0x00, 0x00, 0x01},
        /*path=*/{0x80000057, 0x80000001, 0x00000000});

    const fs::path script_path = WriteFailingMockSignerScript();
    ExternalSigner signer{
        "/bin/sh " + fs::PathToString(script_path),
        "regtest",
        "00000001",
        "mock"};

    std::string error;
    bool signed_ok = true;
    BOOST_CHECK_NO_THROW(signed_ok = signer.SignTransaction(request_psbt, error));
    BOOST_CHECK(!signed_ok);
    BOOST_CHECK(error.find("non-P2MR prevout script has P2MR metadata") != std::string::npos);
    fs::remove(script_path);
}

BOOST_AUTO_TEST_CASE(external_signer_rejects_p2mr_prevout_commitment_mismatch)
{
    CMutableTransaction tx;
    tx.vin.resize(1);
    tx.vin[0].prevout = COutPoint{Txid::FromUint256(uint256::ONE), 0};
    tx.vout.resize(1);
    tx.vout[0].nValue = 1'000;
    tx.vout[0].scriptPubKey = CScript{} << OP_TRUE;

    PartiallySignedTransaction request_psbt{tx};
    const uint256 mismatched_root = Hash(std::vector<unsigned char>{0x02});
    request_psbt.inputs[0].witness_utxo = CTxOut{1'000, BuildP2MROutput(mismatched_root)};
    request_psbt.inputs[0].m_p2mr_leaf_script = {OP_TRUE};
    request_psbt.inputs[0].m_p2mr_control_block = {P2MR_LEAF_VERSION};
    request_psbt.inputs[0].m_p2mr_leaf_version = P2MR_LEAF_VERSION;
    request_psbt.inputs[0].m_p2mr_merkle_root = mismatched_root;

    const std::vector<unsigned char> path_pubkey(MLDSA44_PUBKEY_SIZE, 0x2A);
    request_psbt.inputs[0].m_p2mr_bip32_paths[path_pubkey] = SerializeP2MRKeyOrigin(
        /*fingerprint=*/{0x00, 0x00, 0x00, 0x01},
        /*path=*/{0x80000057, 0x80000001, 0x00000000});

    ExternalSigner signer{
        "false",
        "regtest",
        "00000001",
        "mock"};

    std::string error;
    bool signed_ok = true;
    BOOST_CHECK_NO_THROW(signed_ok = signer.SignTransaction(request_psbt, error));
    BOOST_CHECK(!signed_ok);
    BOOST_CHECK(error.find("does not match prevout commitment") != std::string::npos);
}

BOOST_AUTO_TEST_CASE(external_signer_rejects_conflicting_signer_p2mr_merkle_root)
{
    CMutableTransaction tx;
    tx.vin.resize(1);
    tx.vin[0].prevout = COutPoint{Txid::FromUint256(uint256::ONE), 0};
    tx.vout.resize(1);
    tx.vout[0].nValue = 1'000;
    tx.vout[0].scriptPubKey = CScript{} << OP_TRUE;

    PartiallySignedTransaction request_psbt{tx};
    const uint256 request_root = ConfigureSingleLeafP2MRInput(request_psbt.inputs[0], {OP_TRUE});
    request_psbt.inputs[0].witness_utxo = CTxOut{1'000, BuildP2MROutput(request_root)};
    const std::vector<unsigned char> path_pubkey(MLDSA44_PUBKEY_SIZE, 0x77);
    request_psbt.inputs[0].m_p2mr_bip32_paths[path_pubkey] = SerializeP2MRKeyOrigin(
        /*fingerprint=*/{0x00, 0x00, 0x00, 0x01},
        /*path=*/{0x80000057, 0x80000001, 0x00000000});

    PartiallySignedTransaction signer_response = request_psbt;
    signer_response.inputs[0].m_p2mr_merkle_root = Hash(std::vector<unsigned char>{0xAA});
    const fs::path script_path = WriteStaticMockSignerScriptResponse(
        "{\"psbt\":\"" + EncodePSBTForMockSigner(signer_response) + "\"}");

    ExternalSigner signer{
        "/bin/sh " + fs::PathToString(script_path),
        "regtest",
        "00000001",
        "mock"};

    std::string error;
    BOOST_CHECK(!signer.SignTransaction(request_psbt, error));
    BOOST_CHECK(error.find("conflicting P2MR merkle root") != std::string::npos);
    fs::remove(script_path);
}

BOOST_AUTO_TEST_CASE(external_signer_rejects_p2mr_control_leaf_version_mismatch)
{
    CMutableTransaction tx;
    tx.vin.resize(1);
    tx.vin[0].prevout = COutPoint{Txid::FromUint256(uint256::ONE), 0};
    tx.vout.resize(1);
    tx.vout[0].nValue = 1'000;
    tx.vout[0].scriptPubKey = CScript{} << OP_TRUE;

    PartiallySignedTransaction request_psbt{tx};
    const uint256 request_root = ConfigureSingleLeafP2MRInput(request_psbt.inputs[0], {OP_TRUE});
    request_psbt.inputs[0].witness_utxo = CTxOut{1'000, BuildP2MROutput(request_root)};
    request_psbt.inputs[0].m_p2mr_control_block[0] = static_cast<uint8_t>(P2MR_LEAF_VERSION - 2);

    const std::vector<unsigned char> path_pubkey(MLDSA44_PUBKEY_SIZE, 0x2A);
    request_psbt.inputs[0].m_p2mr_bip32_paths[path_pubkey] = SerializeP2MRKeyOrigin(
        /*fingerprint=*/{0x00, 0x00, 0x00, 0x01},
        /*path=*/{0x80000057, 0x80000001, 0x00000000});

    ExternalSigner signer{
        "false",
        "regtest",
        "00000001",
        "mock"};

    std::string error;
    bool signed_ok = true;
    BOOST_CHECK_NO_THROW(signed_ok = signer.SignTransaction(request_psbt, error));
    BOOST_CHECK(!signed_ok);
    BOOST_CHECK(error.find("control block leaf version mismatch") != std::string::npos);
}

BOOST_AUTO_TEST_CASE(external_signer_requires_p2mr_fingerprint_match_from_p2mr_paths)
{
    CMutableTransaction tx;
    tx.vin.resize(1);
    tx.vin[0].prevout = COutPoint{Txid::FromUint256(uint256::ONE), 0};
    tx.vout.resize(1);
    tx.vout[0].nValue = 1'000;
    tx.vout[0].scriptPubKey = CScript{} << OP_TRUE;

    PartiallySignedTransaction request_psbt{tx};
    const uint256 request_root = ConfigureSingleLeafP2MRInput(request_psbt.inputs[0], {OP_TRUE});
    request_psbt.inputs[0].witness_utxo = CTxOut{1'000, BuildP2MROutput(request_root)};

    const std::vector<unsigned char> path_pubkey(MLDSA44_PUBKEY_SIZE, 0x2A);
    request_psbt.inputs[0].m_p2mr_bip32_paths[path_pubkey] = SerializeP2MRKeyOrigin(
        /*fingerprint=*/{0x00, 0x00, 0x00, 0x02},
        /*path=*/{0x80000057, 0x80000001, 0x00000000});

    CKey ecdsa_key;
    ecdsa_key.MakeNewKey(/*fCompressed=*/true);
    KeyOriginInfo hd_origin;
    hd_origin.fingerprint[0] = 0x00;
    hd_origin.fingerprint[1] = 0x00;
    hd_origin.fingerprint[2] = 0x00;
    hd_origin.fingerprint[3] = 0x01;
    hd_origin.path = {0x8000002C};
    request_psbt.inputs[0].hd_keypaths[ecdsa_key.GetPubKey()] = hd_origin;

    ExternalSigner signer{
        "false",
        "regtest",
        "00000001",
        "mock"};

    std::string error;
    bool signed_ok = true;
    BOOST_CHECK_NO_THROW(signed_ok = signer.SignTransaction(request_psbt, error));
    BOOST_CHECK(!signed_ok);
    BOOST_CHECK(error.find("does not match any P2MR derivation fingerprint") != std::string::npos);
}

BOOST_AUTO_TEST_CASE(p2mr_minimal_if_enforced)
{
    ScriptExecutionData execdata;
    ScriptError err = SCRIPT_ERR_UNKNOWN_ERROR;
    std::vector<std::vector<unsigned char>> stack{{0x02}};
    const CScript script = CScript() << OP_IF << OP_TRUE << OP_ENDIF;
    BOOST_CHECK(!EvalScript(stack, script, SCRIPT_VERIFY_NONE, BaseSignatureChecker{}, SigVersion::P2MR, execdata, &err));
    BOOST_CHECK_EQUAL(err, SCRIPT_ERR_TAPSCRIPT_MINIMALIF);

    std::vector<std::vector<unsigned char>> minimal_stack{{0x01}};
    err = SCRIPT_ERR_UNKNOWN_ERROR;
    BOOST_CHECK(EvalScript(minimal_stack, script, SCRIPT_VERIFY_NONE, BaseSignatureChecker{}, SigVersion::P2MR, execdata, &err));
    BOOST_CHECK_EQUAL(err, SCRIPT_ERR_OK);
}

BOOST_AUTO_TEST_CASE(external_signer_enumerate_parses_p2mr_capabilities)
{
    const fs::path script_path = WriteStaticMockSignerScriptResponse(
        R"([{"fingerprint":"00000001","model":"Mock","capabilities":{"p2mr":true,"pq_algorithms":["ml_dsa_44","slh_dsa_128s"]}}])");

    std::vector<ExternalSigner> signers;
    BOOST_REQUIRE(ExternalSigner::Enumerate("/bin/sh " + fs::PathToString(script_path), signers, "regtest"));
    BOOST_REQUIRE_EQUAL(signers.size(), 1U);
    BOOST_CHECK(signers[0].SupportsP2MR());
    BOOST_REQUIRE_EQUAL(signers[0].SupportedPQAlgorithms().size(), 2U);
    BOOST_CHECK_EQUAL(signers[0].SupportedPQAlgorithms()[0], "ml_dsa_44");
    BOOST_CHECK_EQUAL(signers[0].SupportedPQAlgorithms()[1], "slh_dsa_128s");
    fs::remove(script_path);
}

BOOST_AUTO_TEST_CASE(external_signer_enumerate_defaults_without_p2mr_capabilities)
{
    const fs::path script_path = WriteStaticMockSignerScriptResponse(
        R"([{"fingerprint":"00000002","model":"Mock"}])");

    std::vector<ExternalSigner> signers;
    BOOST_REQUIRE(ExternalSigner::Enumerate("/bin/sh " + fs::PathToString(script_path), signers, "regtest"));
    BOOST_REQUIRE_EQUAL(signers.size(), 1U);
    BOOST_CHECK(!signers[0].SupportsP2MR());
    BOOST_CHECK(signers[0].SupportedPQAlgorithms().empty());
    fs::remove(script_path);
}

BOOST_AUTO_TEST_CASE(external_signer_enumerate_rejects_invalid_fingerprint)
{
    const fs::path script_path = WriteStaticMockSignerScriptResponse(
        R"([{"fingerprint":"bad-fp;echo pwn","model":"Mock"}])");

    std::vector<ExternalSigner> signers;
    BOOST_CHECK_THROW(ExternalSigner::Enumerate("/bin/sh " + fs::PathToString(script_path), signers, "regtest"), std::runtime_error);
    fs::remove(script_path);
}

BOOST_AUTO_TEST_CASE(external_signer_enumerate_rejects_non_string_fingerprint)
{
    const fs::path script_path = WriteStaticMockSignerScriptResponse(
        R"([{"fingerprint":1234,"model":"Mock"}])");

    std::vector<ExternalSigner> signers;
    BOOST_CHECK_THROW(ExternalSigner::Enumerate("/bin/sh " + fs::PathToString(script_path), signers, "regtest"), std::runtime_error);
    fs::remove(script_path);
}

BOOST_AUTO_TEST_CASE(external_signer_enumerate_duplicate_does_not_hide_later_signer)
{
    const fs::path script_path = WriteStaticMockSignerScriptResponse(
        R"([{"fingerprint":"00000001","model":"First"},{"fingerprint":"00000001","model":"Duplicate"},{"fingerprint":"00000002","model":"Second"}])");

    std::vector<ExternalSigner> signers;
    BOOST_REQUIRE(ExternalSigner::Enumerate("/bin/sh " + fs::PathToString(script_path), signers, "regtest"));
    BOOST_REQUIRE_EQUAL(signers.size(), 2U);
    BOOST_CHECK_EQUAL(signers[0].m_fingerprint, "00000001");
    BOOST_CHECK_EQUAL(signers[1].m_fingerprint, "00000002");
    fs::remove(script_path);
}

BOOST_AUTO_TEST_CASE(external_signer_command_args_are_not_shell_quoted)
{
    const fs::path script_path = WriteArgDumpMockSignerScript();
    ExternalSigner signer{
        "/bin/sh " + fs::PathToString(script_path),
        "regtest",
        "00000001",
        "mock"};

    const std::string descriptor = "wpkh(028df1f2e11f6a9f0edba7f2d9f4f11223344556677889900aabbccddeeff001122)";
    const UniValue response = signer.DisplayAddress(descriptor);
    BOOST_REQUIRE(response.isObject());
    BOOST_REQUIRE(response.find_value("argv").isStr());

    const std::string argv_dump = response.find_value("argv").get_str();
    BOOST_CHECK(argv_dump.find("|'00000001'|") == std::string::npos);
    BOOST_CHECK(argv_dump.find("|00000001|") != std::string::npos);
    BOOST_CHECK(argv_dump.find("|" + descriptor) != std::string::npos);
    BOOST_CHECK(argv_dump.find("'" + descriptor + "'") == std::string::npos);
    fs::remove(script_path);
}

BOOST_AUTO_TEST_CASE(external_signer_rejects_invalid_chain_argument)
{
    const fs::path script_path = WriteArgDumpMockSignerScript();
    ExternalSigner signer{
        "/bin/sh " + fs::PathToString(script_path),
        "regtest injected",
        "00000001",
        "mock"};
    BOOST_CHECK_THROW(signer.GetDescriptors(0), std::runtime_error);
    fs::remove(script_path);
}

BOOST_AUTO_TEST_CASE(external_signer_rejects_displayaddress_descriptor_with_whitespace)
{
    const fs::path script_path = WriteArgDumpMockSignerScript();
    ExternalSigner signer{
        "/bin/sh " + fs::PathToString(script_path),
        "regtest",
        "00000001",
        "mock"};

    const std::string descriptor = "wpkh(028df1f2e11f6a9f0edba7f2d9f4f11223344556677889900aabbccddeeff001122) injected";
    BOOST_CHECK_THROW(signer.DisplayAddress(descriptor), std::runtime_error);
    fs::remove(script_path);
}

BOOST_AUTO_TEST_CASE(external_signer_rejects_getp2mrpubkeys_descriptor_with_whitespace)
{
    const fs::path script_path = WriteArgDumpMockSignerScript();
    ExternalSigner signer{
        "/bin/sh " + fs::PathToString(script_path),
        "regtest",
        "00000001",
        "mock"};

    const std::string descriptor = "mr(pk(028df1f2e11f6a9f0edba7f2d9f4f11223344556677889900aabbccddeeff001122),pk(03aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa)) --x";
    BOOST_CHECK_THROW(signer.GetP2MRPubKeys(descriptor, /*index=*/0), std::runtime_error);
    fs::remove(script_path);
}

BOOST_AUTO_TEST_CASE(external_signer_rejects_modified_unsigned_tx)
{
    CMutableTransaction tx;
    tx.vin.resize(1);
    tx.vin[0].prevout = COutPoint{Txid::FromUint256(uint256::ONE), 0};
    tx.vout.resize(1);
    tx.vout[0].nValue = 1'000;
    tx.vout[0].scriptPubKey = CScript{} << OP_TRUE;

    PartiallySignedTransaction request_psbt{tx};
    CKey key;
    key.MakeNewKey(/*fCompressed=*/true);
    KeyOriginInfo origin;
    origin.fingerprint[0] = 0x00;
    origin.fingerprint[1] = 0x00;
    origin.fingerprint[2] = 0x00;
    origin.fingerprint[3] = 0x01;
    origin.path = {0x8000002C};
    request_psbt.inputs[0].hd_keypaths[key.GetPubKey()] = origin;

    PartiallySignedTransaction signer_response = request_psbt;
    signer_response.tx->vout[0].nValue = 2'000;
    const fs::path script_path = WriteStaticMockSignerScriptResponse(
        "{\"psbt\":\"" + EncodePSBTForMockSigner(signer_response) + "\"}");

    ExternalSigner signer{
        "/bin/sh " + fs::PathToString(script_path),
        "regtest",
        "00000001",
        "mock"};

    std::string error;
    bool signed_ok = true;
    BOOST_CHECK_NO_THROW(signed_ok = signer.SignTransaction(request_psbt, error));
    BOOST_CHECK(!signed_ok);
    BOOST_CHECK(error.find("modified transaction") != std::string::npos);
    fs::remove(script_path);
}

BOOST_AUTO_TEST_CASE(external_signer_rejects_p2mr_material_for_non_p2mr_input)
{
    CMutableTransaction tx;
    tx.vin.resize(1);
    tx.vin[0].prevout = COutPoint{Txid::FromUint256(uint256::ONE), 0};
    tx.vout.resize(1);
    tx.vout[0].nValue = 1'000;
    tx.vout[0].scriptPubKey = CScript{} << OP_TRUE;

    PartiallySignedTransaction request_psbt{tx};
    request_psbt.inputs[0].witness_utxo = CTxOut{1'000, CScript{} << OP_TRUE};

    CKey ecdsa_key;
    ecdsa_key.MakeNewKey(/*fCompressed=*/true);
    KeyOriginInfo hd_origin;
    hd_origin.fingerprint[0] = 0x00;
    hd_origin.fingerprint[1] = 0x00;
    hd_origin.fingerprint[2] = 0x00;
    hd_origin.fingerprint[3] = 0x01;
    hd_origin.path = {0x8000002C};
    request_psbt.inputs[0].hd_keypaths[ecdsa_key.GetPubKey()] = hd_origin;

    PartiallySignedTransaction signer_response = request_psbt;
    const std::vector<unsigned char> p2mr_pubkey(MLDSA44_PUBKEY_SIZE, 0x73);
    signer_response.inputs[0].m_p2mr_pq_sigs[std::make_pair(uint256::ONE, p2mr_pubkey)] =
        std::vector<unsigned char>(MLDSA44_SIGNATURE_SIZE, 0x42);

    const fs::path script_path = WriteStaticMockSignerScriptResponse(
        "{\"psbt\":\"" + EncodePSBTForMockSigner(signer_response) + "\"}");

    ExternalSigner signer{
        "/bin/sh " + fs::PathToString(script_path),
        "regtest",
        "00000001",
        "mock"};

    std::string error;
    bool signed_ok = true;
    BOOST_CHECK_NO_THROW(signed_ok = signer.SignTransaction(request_psbt, error));
    BOOST_CHECK(!signed_ok);
    BOOST_CHECK(error.find("non-P2MR input") != std::string::npos);
    fs::remove(script_path);
}

BOOST_AUTO_TEST_CASE(external_signer_rejects_p2mr_material_without_prevout_script)
{
    CMutableTransaction tx;
    tx.vin.resize(1);
    tx.vin[0].prevout = COutPoint{Txid::FromUint256(uint256::ONE), 0};
    tx.vout.resize(1);
    tx.vout[0].nValue = 1'000;
    tx.vout[0].scriptPubKey = CScript{} << OP_TRUE;

    PartiallySignedTransaction request_psbt{tx};
    CKey ecdsa_key;
    ecdsa_key.MakeNewKey(/*fCompressed=*/true);
    KeyOriginInfo hd_origin;
    hd_origin.fingerprint[0] = 0x00;
    hd_origin.fingerprint[1] = 0x00;
    hd_origin.fingerprint[2] = 0x00;
    hd_origin.fingerprint[3] = 0x01;
    hd_origin.path = {0x8000002C};
    request_psbt.inputs[0].hd_keypaths[ecdsa_key.GetPubKey()] = hd_origin;

    PartiallySignedTransaction signer_response = request_psbt;
    const std::vector<unsigned char> p2mr_pubkey(MLDSA44_PUBKEY_SIZE, 0x74);
    signer_response.inputs[0].m_p2mr_pq_sigs[std::make_pair(uint256::ONE, p2mr_pubkey)] =
        std::vector<unsigned char>(MLDSA44_SIGNATURE_SIZE, 0x43);

    const fs::path script_path = WriteStaticMockSignerScriptResponse(
        "{\"psbt\":\"" + EncodePSBTForMockSigner(signer_response) + "\"}");

    ExternalSigner signer{
        "/bin/sh " + fs::PathToString(script_path),
        "regtest",
        "00000001",
        "mock"};

    std::string error;
    bool signed_ok = true;
    BOOST_CHECK_NO_THROW(signed_ok = signer.SignTransaction(request_psbt, error));
    BOOST_CHECK(!signed_ok);
    BOOST_CHECK(error.find("without prevout script") != std::string::npos);
    fs::remove(script_path);
}

BOOST_AUTO_TEST_CASE(external_signer_preserves_existing_psbt_input_metadata)
{
    CMutableTransaction tx;
    tx.vin.resize(1);
    tx.vin[0].prevout = COutPoint{Txid::FromUint256(uint256::ONE), 0};
    tx.vout.resize(1);
    tx.vout[0].nValue = 1'000;
    tx.vout[0].scriptPubKey = CScript{} << OP_TRUE;

    PartiallySignedTransaction request_psbt{tx};
    CKey key;
    key.MakeNewKey(/*fCompressed=*/true);
    KeyOriginInfo origin;
    origin.fingerprint[0] = 0x00;
    origin.fingerprint[1] = 0x00;
    origin.fingerprint[2] = 0x00;
    origin.fingerprint[3] = 0x01;
    origin.path = {0x8000002C};
    request_psbt.inputs[0].hd_keypaths[key.GetPubKey()] = origin;

    const std::vector<unsigned char> unknown_key{0xFC, 0x01};
    const std::vector<unsigned char> unknown_value{0x99, 0x01};
    request_psbt.inputs[0].unknown.emplace(unknown_key, unknown_value);

    PartiallySignedTransaction signer_response = request_psbt;
    signer_response.inputs[0].unknown.clear();
    const fs::path script_path = WriteStaticMockSignerScriptResponse(
        "{\"psbt\":\"" + EncodePSBTForMockSigner(signer_response) + "\"}");

    ExternalSigner signer{
        "/bin/sh " + fs::PathToString(script_path),
        "regtest",
        "00000001",
        "mock"};

    std::string error;
    bool signed_ok = false;
    BOOST_CHECK_NO_THROW(signed_ok = signer.SignTransaction(request_psbt, error));
    BOOST_CHECK(signed_ok);
    BOOST_CHECK_EQUAL(error, "");
    BOOST_CHECK(request_psbt.inputs[0].unknown.contains(unknown_key));
    fs::remove(script_path);
}

BOOST_AUTO_TEST_CASE(pq_key_derivation_deterministic)
{
    const std::vector<unsigned char> master_seed = ParseHex(
        "000102030405060708090a0b0c0d0e0f"
        "101112131415161718191a1b1c1d1e1f"
        "202122232425262728292a2b2c2d2e2f"
        "303132333435363738393a3b3c3d3e3f");
    BOOST_REQUIRE(!master_seed.empty());

    const auto seed_a = wallet::DerivePQSeedFromBIP39(master_seed, PQAlgorithm::ML_DSA_44, /*coin_type=*/1, /*account=*/0, /*change=*/0, /*index=*/7);
    const auto seed_b = wallet::DerivePQSeedFromBIP39(master_seed, PQAlgorithm::ML_DSA_44, /*coin_type=*/1, /*account=*/0, /*change=*/0, /*index=*/7);
    BOOST_CHECK(seed_a == seed_b);

    const auto key_a = wallet::DerivePQKeyFromBIP39(master_seed, PQAlgorithm::ML_DSA_44, /*coin_type=*/1, /*account=*/0, /*change=*/0, /*index=*/7);
    const auto key_b = wallet::DerivePQKeyFromBIP39(master_seed, PQAlgorithm::ML_DSA_44, /*coin_type=*/1, /*account=*/0, /*change=*/0, /*index=*/7);
    BOOST_REQUIRE(key_a.has_value());
    BOOST_REQUIRE(key_b.has_value());
    BOOST_CHECK(key_a->IsValid());
    BOOST_CHECK(key_b->IsValid());
    BOOST_CHECK(key_a->GetPubKey() == key_b->GetPubKey());

    const auto key_diff_index = wallet::DerivePQKeyFromBIP39(master_seed, PQAlgorithm::ML_DSA_44, /*coin_type=*/1, /*account=*/0, /*change=*/0, /*index=*/8);
    BOOST_REQUIRE(key_diff_index.has_value());
    BOOST_CHECK(key_diff_index->GetPubKey() != key_a->GetPubKey());

    const auto key_diff_algo = wallet::DerivePQKeyFromBIP39(master_seed, PQAlgorithm::SLH_DSA_128S, /*coin_type=*/1, /*account=*/0, /*change=*/0, /*index=*/7);
    BOOST_REQUIRE(key_diff_algo.has_value());
    BOOST_CHECK(key_diff_algo->GetPubKey() != key_a->GetPubKey());
}

BOOST_AUTO_TEST_SUITE_END()
