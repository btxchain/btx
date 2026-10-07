// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <hash.h>
#include <pqkey.h>
#include <primitives/transaction.h>
#include <script/interpreter.h>
#include <script/pqm.h>
#include <script/script_error.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <limits>
#include <vector>

namespace {

class P2MRTemplateChecker final : public BaseSignatureChecker
{
public:
    explicit P2MRTemplateChecker(bool locktime_ok) : m_locktime_ok(locktime_ok) {}

    bool CheckPQSignature(Span<const unsigned char>, Span<const unsigned char>, PQAlgorithm, uint8_t, SigVersion, ScriptExecutionData&, bool) const override
    {
        return true;
    }

    bool CheckLockTime(const CScriptNum&) const override
    {
        return m_locktime_ok;
    }

private:
    bool m_locktime_ok;
};

std::vector<unsigned char> Sha256Bytes(Span<const unsigned char> data)
{
    uint256 hash;
    CSHA256().Write(data.data(), data.size()).Finalize(hash.begin());
    return {hash.begin(), hash.end()};
}

std::vector<unsigned char> Hash160Bytes(Span<const unsigned char> data)
{
    const uint160 hash = Hash160(data);
    return {hash.begin(), hash.end()};
}

bool EvalP2MRScript(const CScript& script, std::vector<std::vector<unsigned char>>& stack, const BaseSignatureChecker& checker, ScriptExecutionData& execdata, ScriptError& serror)
{
    constexpr unsigned int flags = SCRIPT_VERIFY_NULLFAIL | SCRIPT_VERIFY_CHECKLOCKTIMEVERIFY;
    return EvalScript(stack, script, flags, checker, SigVersion::P2MR, execdata, &serror);
}

} // namespace

BOOST_FIXTURE_TEST_SUITE(script_htlc_templates_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(legacy_htlc_leaf_valid_build)
{
    const std::vector<unsigned char> preimage_hash(20, 0x11);
    const std::vector<unsigned char> oracle_pubkey(MLDSA44_PUBKEY_SIZE, 0x22);
    const std::vector<unsigned char> script = BuildP2MRHTLCLeaf(preimage_hash, PQAlgorithm::ML_DSA_44, oracle_pubkey);
    BOOST_REQUIRE(!script.empty());

    CScript expected;
    expected << preimage_hash << OP_OVER << OP_HASH160 << OP_EQUALVERIFY
             << oracle_pubkey << OP_CHECKSIGFROMSTACK;
    BOOST_CHECK_EQUAL_COLLECTIONS(script.begin(), script.end(), expected.begin(), expected.end());
}

BOOST_AUTO_TEST_CASE(htlc_tx_leaf_valid_build)
{
    const std::vector<unsigned char> preimage_hash(20, 0x31);
    const std::vector<unsigned char> claimant_pubkey(MLDSA44_PUBKEY_SIZE, 0x32);
    const std::vector<unsigned char> script =
        BuildP2MRHTLCTxLeaf(preimage_hash, PQAlgorithm::ML_DSA_44, claimant_pubkey);
    BOOST_REQUIRE(!script.empty());

    CScript expected;
    expected << preimage_hash << OP_OVER << OP_HASH160 << OP_EQUALVERIFY << OP_DROP
             << claimant_pubkey << OP_CHECKSIG_MLDSA;
    BOOST_CHECK_EQUAL_COLLECTIONS(script.begin(), script.end(), expected.begin(), expected.end());
}

BOOST_AUTO_TEST_CASE(htlc_sha256_leaf_valid_build)
{
    const std::vector<unsigned char> preimage_hash(32, 0x41);
    const std::vector<unsigned char> claimant_pubkey(MLDSA44_PUBKEY_SIZE, 0x42);
    const std::vector<unsigned char> script =
        BuildP2MRHTLCSha256Leaf(preimage_hash, PQAlgorithm::ML_DSA_44, claimant_pubkey);
    BOOST_REQUIRE(!script.empty());

    CScript expected;
    expected << OP_SIZE << int64_t{32} << OP_EQUALVERIFY
             << OP_SHA256 << preimage_hash << OP_EQUALVERIFY
             << claimant_pubkey << OP_CHECKSIG_MLDSA;
    BOOST_CHECK_EQUAL_COLLECTIONS(script.begin(), script.end(), expected.begin(), expected.end());
}

BOOST_AUTO_TEST_CASE(htlc_leaf_invalid_preimage_size)
{
    const std::vector<unsigned char> wrong_hash(19, 0x01);
    const std::vector<unsigned char> oracle_pubkey(MLDSA44_PUBKEY_SIZE, 0x02);
    BOOST_CHECK(BuildP2MRHTLCLeaf(wrong_hash, PQAlgorithm::ML_DSA_44, oracle_pubkey).empty());
    BOOST_CHECK(BuildP2MRHTLCSha256Leaf(wrong_hash, PQAlgorithm::ML_DSA_44, oracle_pubkey).empty());
}

BOOST_AUTO_TEST_CASE(refund_leaf_valid_build)
{
    const std::vector<unsigned char> sender_pubkey(MLDSA44_PUBKEY_SIZE, 0x33);
    const std::vector<unsigned char> script = BuildP2MRRefundLeaf(/*timeout=*/500, PQAlgorithm::ML_DSA_44, sender_pubkey);
    BOOST_REQUIRE(!script.empty());

    CScript expected;
    expected << CScriptNum{500} << OP_CHECKLOCKTIMEVERIFY << OP_DROP << sender_pubkey << OP_CHECKSIG_MLDSA;
    BOOST_CHECK_EQUAL_COLLECTIONS(script.begin(), script.end(), expected.begin(), expected.end());
}

BOOST_AUTO_TEST_CASE(htlc_leaf_size_within_policy)
{
    const std::vector<unsigned char> preimage_hash(32, 0x44);
    const std::vector<unsigned char> oracle_pubkey(MLDSA44_PUBKEY_SIZE, 0x55);
    const std::vector<unsigned char> script = BuildP2MRHTLCSha256Leaf(
        preimage_hash, PQAlgorithm::ML_DSA_44, oracle_pubkey);
    BOOST_REQUIRE(!script.empty());
    BOOST_CHECK_LT(script.size(), 1650U);
}

BOOST_AUTO_TEST_CASE(htlc_correct_preimage_succeeds)
{
    CPQKey oracle_key;
    oracle_key.MakeNewKey(PQAlgorithm::ML_DSA_44);
    BOOST_REQUIRE(oracle_key.IsValid());

    const std::vector<unsigned char> preimage(32, 0x66);
    const std::vector<unsigned char> preimage_hash = Sha256Bytes(preimage);
    const std::vector<unsigned char> script_bytes = BuildP2MRHTLCSha256Leaf(
        preimage_hash, PQAlgorithm::ML_DSA_44, oracle_key.GetPubKey());
    BOOST_REQUIRE(!script_bytes.empty());
    const CScript script{script_bytes.begin(), script_bytes.end()};

    // The template checker accepts a correctly-sized transaction signature; full
    // transaction binding is exercised by wallet_htlc_atomicswap.py.
    std::vector<std::vector<unsigned char>> stack;
    stack.push_back(std::vector<unsigned char>(MLDSA44_SIGNATURE_SIZE, 0x01));
    stack.push_back(preimage);

    ScriptExecutionData execdata;
    execdata.m_validation_weight_left_init = true;
    execdata.m_validation_weight_left = 5000;
    ScriptError serror = SCRIPT_ERR_OK;
    const P2MRTemplateChecker checker{/*locktime_ok=*/true};
    BOOST_REQUIRE(EvalP2MRScript(script, stack, checker, execdata, serror));
    BOOST_CHECK_EQUAL(serror, SCRIPT_ERR_OK);
    // Consensus (ExecuteWitnessScript) requires exactly one truthy cleanstack item.
    BOOST_REQUIRE_EQUAL(stack.size(), 1U);
    BOOST_CHECK_EQUAL(CScriptNum(stack.back(), /*fRequireMinimal=*/true).GetInt64(), 1);
}

BOOST_AUTO_TEST_CASE(htlc_wrong_preimage_fails)
{
    CPQKey oracle_key;
    oracle_key.MakeNewKey(PQAlgorithm::ML_DSA_44);
    BOOST_REQUIRE(oracle_key.IsValid());

    const std::vector<unsigned char> correct_preimage(32, 0x77);
    const std::vector<unsigned char> wrong_preimage(32, 0x88);
    const std::vector<unsigned char> preimage_hash = Sha256Bytes(correct_preimage);
    const std::vector<unsigned char> script_bytes = BuildP2MRHTLCSha256Leaf(
        preimage_hash, PQAlgorithm::ML_DSA_44, oracle_key.GetPubKey());
    BOOST_REQUIRE(!script_bytes.empty());
    const CScript script{script_bytes.begin(), script_bytes.end()};

    std::vector<std::vector<unsigned char>> stack;
    stack.push_back(std::vector<unsigned char>(MLDSA44_SIGNATURE_SIZE, 0x01));
    stack.push_back(wrong_preimage);

    ScriptExecutionData execdata;
    execdata.m_validation_weight_left_init = true;
    execdata.m_validation_weight_left = 5000;
    ScriptError serror = SCRIPT_ERR_OK;
    const P2MRTemplateChecker checker{/*locktime_ok=*/true};
    BOOST_CHECK(!EvalP2MRScript(script, stack, checker, execdata, serror));
    BOOST_CHECK_EQUAL(serror, SCRIPT_ERR_EQUALVERIFY);
}

BOOST_AUTO_TEST_CASE(refund_after_timeout_succeeds)
{
    const std::vector<unsigned char> sender_pubkey(MLDSA44_PUBKEY_SIZE, 0x99);
    const std::vector<unsigned char> script_bytes = BuildP2MRRefundLeaf(/*timeout=*/700, PQAlgorithm::ML_DSA_44, sender_pubkey);
    BOOST_REQUIRE(!script_bytes.empty());
    const CScript script{script_bytes.begin(), script_bytes.end()};

    std::vector<std::vector<unsigned char>> stack;
    stack.push_back(std::vector<unsigned char>(MLDSA44_SIGNATURE_SIZE, 0x01));

    ScriptExecutionData execdata;
    execdata.m_validation_weight_left_init = true;
    execdata.m_validation_weight_left = 5000;
    ScriptError serror = SCRIPT_ERR_OK;
    const P2MRTemplateChecker checker{/*locktime_ok=*/true};
    BOOST_REQUIRE(EvalP2MRScript(script, stack, checker, execdata, serror));
    BOOST_CHECK_EQUAL(serror, SCRIPT_ERR_OK);
    BOOST_REQUIRE_EQUAL(stack.size(), 1U);
    BOOST_CHECK_EQUAL(CScriptNum(stack.back(), /*fRequireMinimal=*/true).GetInt64(), 1);
}

BOOST_AUTO_TEST_CASE(refund_before_timeout_fails)
{
    const std::vector<unsigned char> sender_pubkey(MLDSA44_PUBKEY_SIZE, 0xaa);
    const std::vector<unsigned char> script_bytes = BuildP2MRRefundLeaf(/*timeout=*/900, PQAlgorithm::ML_DSA_44, sender_pubkey);
    BOOST_REQUIRE(!script_bytes.empty());
    const CScript script{script_bytes.begin(), script_bytes.end()};

    std::vector<std::vector<unsigned char>> stack;
    stack.push_back(std::vector<unsigned char>(MLDSA44_SIGNATURE_SIZE, 0x01));

    ScriptExecutionData execdata;
    execdata.m_validation_weight_left_init = true;
    execdata.m_validation_weight_left = 5000;
    ScriptError serror = SCRIPT_ERR_OK;
    const P2MRTemplateChecker checker{/*locktime_ok=*/false};
    BOOST_CHECK(!EvalP2MRScript(script, stack, checker, execdata, serror));
    BOOST_CHECK_EQUAL(serror, SCRIPT_ERR_UNSATISFIED_LOCKTIME);
}

BOOST_AUTO_TEST_CASE(csv_multisig_rejects_non_bip68_sequence_bits)
{
    // csv_multi_pq requires >=2 pubkeys; threshold-1 of a 2-key set is the
    // smallest valid BuildP2MRCSVMultisigScript input.
    const std::vector<unsigned char> pk1(MLDSA44_PUBKEY_SIZE, 0x12);
    const std::vector<unsigned char> pk2(MLDSA44_PUBKEY_SIZE, 0x13);
    const std::vector<std::pair<PQAlgorithm, std::vector<unsigned char>>> keys{
        {PQAlgorithm::ML_DSA_44, pk1},
        {PQAlgorithm::ML_DSA_44, pk2},
    };
    const auto build = [&](int64_t sequence) {
        return BuildP2MRCSVMultisigScript(sequence, /*threshold=*/1, keys);
    };

    BOOST_CHECK(!build(144).empty());
    BOOST_CHECK(!build(144 | CTxIn::SEQUENCE_LOCKTIME_TYPE_FLAG).empty());
    BOOST_CHECK(build(100000).empty());
    BOOST_CHECK(build(int64_t{1} << 16).empty());
    BOOST_CHECK(build(static_cast<int64_t>(CTxIn::SEQUENCE_LOCKTIME_DISABLE_FLAG)).empty());
    BOOST_CHECK(build(0).empty());
    BOOST_CHECK(build(static_cast<int64_t>(std::numeric_limits<int32_t>::max()) + 1).empty());
}

BOOST_AUTO_TEST_CASE(two_leaf_merkle_htlc)
{
    CPQKey oracle_key;
    oracle_key.MakeNewKey(PQAlgorithm::ML_DSA_44);
    BOOST_REQUIRE(oracle_key.IsValid());

    const std::vector<unsigned char> preimage_hash(32, 0xbb);
    const std::vector<unsigned char> sender_pubkey(MLDSA44_PUBKEY_SIZE, 0xcc);
    const std::vector<unsigned char> htlc_leaf = BuildP2MRHTLCSha256Leaf(
        preimage_hash, PQAlgorithm::ML_DSA_44, oracle_key.GetPubKey());
    const std::vector<unsigned char> refund_leaf = BuildP2MRRefundLeaf(/*timeout=*/1024, PQAlgorithm::ML_DSA_44, sender_pubkey);
    BOOST_REQUIRE(!htlc_leaf.empty());
    BOOST_REQUIRE(!refund_leaf.empty());

    const uint256 htlc_hash = ComputeP2MRLeafHash(P2MR_LEAF_VERSION, htlc_leaf);
    const uint256 refund_hash = ComputeP2MRLeafHash(P2MR_LEAF_VERSION, refund_leaf);
    const uint256 root = ComputeP2MRMerkleRoot({htlc_hash, refund_hash});
    const std::vector<unsigned char> program(root.begin(), root.end());

    std::vector<unsigned char> htlc_control;
    htlc_control.push_back(P2MR_LEAF_VERSION);
    htlc_control.insert(htlc_control.end(), refund_hash.begin(), refund_hash.end());
    BOOST_CHECK(VerifyP2MRCommitment(htlc_control, program, htlc_hash));

    std::vector<unsigned char> refund_control;
    refund_control.push_back(P2MR_LEAF_VERSION);
    refund_control.insert(refund_control.end(), htlc_hash.begin(), htlc_hash.end());
    BOOST_CHECK(VerifyP2MRCommitment(refund_control, program, refund_hash));
}

BOOST_AUTO_TEST_CASE(htlc_sha256_leaf_rejects_other_preimage_length)
{
    CPQKey oracle_key;
    oracle_key.MakeNewKey(PQAlgorithm::ML_DSA_44);
    BOOST_REQUIRE(oracle_key.IsValid());

    const std::vector<unsigned char> preimage(64, 0x5a);
    const std::vector<unsigned char> preimage_hash = Sha256Bytes(preimage);
    const std::vector<unsigned char> script_bytes = BuildP2MRHTLCSha256Leaf(
        preimage_hash, PQAlgorithm::ML_DSA_44, oracle_key.GetPubKey());
    BOOST_REQUIRE(!script_bytes.empty());
    const CScript script{script_bytes.begin(), script_bytes.end()};

    std::vector<std::vector<unsigned char>> stack;
    stack.push_back(std::vector<unsigned char>(MLDSA44_SIGNATURE_SIZE, 0x01));
    stack.push_back(preimage);

    ScriptExecutionData execdata;
    execdata.m_validation_weight_left_init = true;
    execdata.m_validation_weight_left = 5000;
    ScriptError serror = SCRIPT_ERR_OK;
    const P2MRTemplateChecker checker{/*locktime_ok=*/true};
    BOOST_CHECK(!EvalP2MRScript(script, stack, checker, execdata, serror));
    BOOST_CHECK_EQUAL(serror, SCRIPT_ERR_EQUALVERIFY);
}

BOOST_AUTO_TEST_CASE(unpinned_htlc_leaves_accept_non32_preimage_under_flag)
{
    CPQKey oracle_key;
    oracle_key.MakeNewKey(PQAlgorithm::ML_DSA_44);
    BOOST_REQUIRE(oracle_key.IsValid());

    constexpr unsigned int base_flags{SCRIPT_VERIFY_P2SH | SCRIPT_VERIFY_WITNESS};
    constexpr unsigned int pinned_flags{base_flags | SCRIPT_VERIFY_P2MR_HTLC_PREIMAGE32};
    const P2MRTemplateChecker checker{/*locktime_ok=*/true};

    auto spend = [&](const std::vector<unsigned char>& leaf, const std::vector<unsigned char>& preimage, unsigned int flags) {
        const uint256 leaf_hash = ComputeP2MRLeafHash(P2MR_LEAF_VERSION, leaf);
        const uint256 root = ComputeP2MRMerkleRoot({leaf_hash});
        CScript script_pubkey;
        script_pubkey << OP_2 << std::vector<unsigned char>(root.begin(), root.end());
        CScriptWitness witness;
        witness.stack.push_back(std::vector<unsigned char>(MLDSA44_SIGNATURE_SIZE, 0x01));
        witness.stack.push_back(preimage);
        witness.stack.push_back(leaf);
        witness.stack.push_back({P2MR_LEAF_VERSION});
        ScriptError err = SCRIPT_ERR_OK;
        const bool ok = VerifyScript(CScript(), script_pubkey, &witness, flags, checker, &err);
        return std::pair<bool, ScriptError>{ok, err};
    };

    const std::vector<unsigned char> preimage32(32, 0x11);
    const std::vector<unsigned char> preimage64(64, 0x22);
    const std::vector<unsigned char> preimage20(20, 0x33);

    // Legacy SHA-256: no OP_SIZE in the committed script. A matching preimage
    // of any length is consensus-valid with the 32-byte flag set.
    const std::vector<unsigned char> legacy64 = BuildP2MRHTLCSha256LegacyLeaf(
        Sha256Bytes(preimage64), PQAlgorithm::ML_DSA_44, oracle_key.GetPubKey());
    BOOST_REQUIRE(!legacy64.empty());
    BOOST_CHECK(!P2MRClaimLeafPinsPreimageLength(legacy64));
    const auto legacy_pinned = spend(legacy64, preimage64, pinned_flags);
    BOOST_CHECK(legacy_pinned.first);
    BOOST_CHECK_EQUAL(legacy_pinned.second, SCRIPT_ERR_OK);
    const auto legacy_base = spend(legacy64, preimage64, base_flags);
    BOOST_CHECK(legacy_base.first);
    BOOST_CHECK_EQUAL(legacy_base.second, SCRIPT_ERR_OK);

    const std::vector<unsigned char> legacy32 = BuildP2MRHTLCSha256LegacyLeaf(
        Sha256Bytes(preimage32), PQAlgorithm::ML_DSA_44, oracle_key.GetPubKey());
    const auto legacy32_ok = spend(legacy32, preimage32, pinned_flags);
    BOOST_CHECK(legacy32_ok.first);
    BOOST_CHECK_EQUAL(legacy32_ok.second, SCRIPT_ERR_OK);

    // HASH160 htlc_tx: same rule. The digest matches; the length is not pinned.
    const std::vector<unsigned char> tx20 = BuildP2MRHTLCTxLeaf(
        Hash160Bytes(preimage20), PQAlgorithm::ML_DSA_44, oracle_key.GetPubKey());
    BOOST_REQUIRE(!tx20.empty());
    BOOST_CHECK(!P2MRClaimLeafPinsPreimageLength(tx20));
    const auto tx_pinned = spend(tx20, preimage20, pinned_flags);
    BOOST_CHECK(tx_pinned.first);
    BOOST_CHECK_EQUAL(tx_pinned.second, SCRIPT_ERR_OK);

    const std::vector<unsigned char> tx64 = BuildP2MRHTLCTxLeaf(
        Hash160Bytes(preimage64), PQAlgorithm::ML_DSA_44, oracle_key.GetPubKey());
    const auto tx64_pinned = spend(tx64, preimage64, pinned_flags);
    BOOST_CHECK(tx64_pinned.first);
    BOOST_CHECK_EQUAL(tx64_pinned.second, SCRIPT_ERR_OK);

    // New htlc_sha256 leaf embeds OP_SIZE 32 OP_EQUALVERIFY. A matching
    // non-32-byte preimage fails under the flag (defense in depth for this
    // format only) and without it (the committed script).
    const std::vector<unsigned char> pinned_leaf = BuildP2MRHTLCSha256Leaf(
        Sha256Bytes(preimage64), PQAlgorithm::ML_DSA_44, oracle_key.GetPubKey());
    BOOST_REQUIRE(!pinned_leaf.empty());
    BOOST_CHECK(P2MRClaimLeafPinsPreimageLength(pinned_leaf));
    const auto pinned_flag = spend(pinned_leaf, preimage64, pinned_flags);
    BOOST_CHECK(!pinned_flag.first);
    BOOST_CHECK_EQUAL(pinned_flag.second, SCRIPT_ERR_P2MR_HTLC_PREIMAGE_SIZE);
    const auto pinned_script = spend(pinned_leaf, preimage64, base_flags);
    BOOST_CHECK(!pinned_script.first);
    BOOST_CHECK_EQUAL(pinned_script.second, SCRIPT_ERR_EQUALVERIFY);

    const std::vector<unsigned char> pinned32 = BuildP2MRHTLCSha256Leaf(
        Sha256Bytes(preimage32), PQAlgorithm::ML_DSA_44, oracle_key.GetPubKey());
    const auto pinned32_ok = spend(pinned32, preimage32, pinned_flags);
    BOOST_CHECK(pinned32_ok.first);
    BOOST_CHECK_EQUAL(pinned32_ok.second, SCRIPT_ERR_OK);
}

BOOST_AUTO_TEST_SUITE_END()
