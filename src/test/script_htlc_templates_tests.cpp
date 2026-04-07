// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <hash.h>
#include <pqkey.h>
#include <script/interpreter.h>
#include <script/pqm.h>
#include <script/script_error.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <vector>

namespace {

class P2MRTemplateChecker final : public BaseSignatureChecker
{
public:
    explicit P2MRTemplateChecker(bool locktime_ok) : m_locktime_ok(locktime_ok) {}

    bool CheckPQSignature(Span<const unsigned char>, Span<const unsigned char>, PQAlgorithm, uint8_t, SigVersion, ScriptExecutionData&) const override
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

BOOST_AUTO_TEST_CASE(htlc_leaf_valid_build)
{
    const std::vector<unsigned char> preimage_hash(20, 0x11);
    const std::vector<unsigned char> oracle_pubkey(MLDSA44_PUBKEY_SIZE, 0x22);
    const std::vector<unsigned char> script = BuildP2MRHTLCLeaf(preimage_hash, PQAlgorithm::ML_DSA_44, oracle_pubkey);
    BOOST_REQUIRE(!script.empty());

    CScript expected;
    expected << preimage_hash << OP_OVER << OP_HASH160 << OP_EQUALVERIFY
             << oracle_pubkey << OP_CHECKSIGFROMSTACK << OP_VERIFY << OP_DROP;
    BOOST_CHECK_EQUAL_COLLECTIONS(script.begin(), script.end(), expected.begin(), expected.end());
}

BOOST_AUTO_TEST_CASE(htlc_leaf_invalid_preimage_size)
{
    const std::vector<unsigned char> wrong_hash(19, 0x01);
    const std::vector<unsigned char> oracle_pubkey(MLDSA44_PUBKEY_SIZE, 0x02);
    BOOST_CHECK(BuildP2MRHTLCLeaf(wrong_hash, PQAlgorithm::ML_DSA_44, oracle_pubkey).empty());
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
    const std::vector<unsigned char> preimage_hash(20, 0x44);
    const std::vector<unsigned char> oracle_pubkey(MLDSA44_PUBKEY_SIZE, 0x55);
    const std::vector<unsigned char> script = BuildP2MRHTLCLeaf(preimage_hash, PQAlgorithm::ML_DSA_44, oracle_pubkey);
    BOOST_REQUIRE(!script.empty());
    BOOST_CHECK_LT(script.size(), 1650U);
}

BOOST_AUTO_TEST_CASE(htlc_correct_preimage_succeeds)
{
    CPQKey oracle_key;
    oracle_key.MakeNewKey(PQAlgorithm::ML_DSA_44);
    BOOST_REQUIRE(oracle_key.IsValid());

    const std::vector<unsigned char> preimage(32, 0x66);
    const std::vector<unsigned char> preimage_hash = Hash160Bytes(preimage);
    const std::vector<unsigned char> script_bytes = BuildP2MRHTLCLeaf(preimage_hash, PQAlgorithm::ML_DSA_44, oracle_key.GetPubKey());
    BOOST_REQUIRE(!script_bytes.empty());
    const CScript script{script_bytes.begin(), script_bytes.end()};

    HashWriter hasher = HASHER_CSFS;
    hasher.write(MakeByteSpan(preimage));
    const uint256 msg_hash = hasher.GetSHA256();
    std::vector<unsigned char> oracle_sig;
    BOOST_REQUIRE(oracle_key.Sign(msg_hash, oracle_sig));

    std::vector<std::vector<unsigned char>> stack;
    stack.push_back(std::vector<unsigned char>{0x01});
    stack.push_back(oracle_sig);
    stack.push_back(preimage);

    ScriptExecutionData execdata;
    execdata.m_validation_weight_left_init = true;
    execdata.m_validation_weight_left = 5000;
    ScriptError serror = SCRIPT_ERR_OK;
    const P2MRTemplateChecker checker{/*locktime_ok=*/true};
    BOOST_REQUIRE(EvalP2MRScript(script, stack, checker, execdata, serror));
    BOOST_CHECK_EQUAL(serror, SCRIPT_ERR_OK);
    BOOST_CHECK(stack.empty());
}

BOOST_AUTO_TEST_CASE(htlc_wrong_preimage_fails)
{
    CPQKey oracle_key;
    oracle_key.MakeNewKey(PQAlgorithm::ML_DSA_44);
    BOOST_REQUIRE(oracle_key.IsValid());

    const std::vector<unsigned char> correct_preimage(32, 0x77);
    const std::vector<unsigned char> wrong_preimage(32, 0x88);
    const std::vector<unsigned char> preimage_hash = Hash160Bytes(correct_preimage);
    const std::vector<unsigned char> script_bytes = BuildP2MRHTLCLeaf(preimage_hash, PQAlgorithm::ML_DSA_44, oracle_key.GetPubKey());
    BOOST_REQUIRE(!script_bytes.empty());
    const CScript script{script_bytes.begin(), script_bytes.end()};

    HashWriter hasher = HASHER_CSFS;
    hasher.write(MakeByteSpan(correct_preimage));
    const uint256 msg_hash = hasher.GetSHA256();
    std::vector<unsigned char> oracle_sig;
    BOOST_REQUIRE(oracle_key.Sign(msg_hash, oracle_sig));

    std::vector<std::vector<unsigned char>> stack;
    stack.push_back(std::vector<unsigned char>{0x01});
    stack.push_back(oracle_sig);
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

BOOST_AUTO_TEST_CASE(two_leaf_merkle_htlc)
{
    CPQKey oracle_key;
    oracle_key.MakeNewKey(PQAlgorithm::ML_DSA_44);
    BOOST_REQUIRE(oracle_key.IsValid());

    const std::vector<unsigned char> preimage_hash(20, 0xbb);
    const std::vector<unsigned char> sender_pubkey(MLDSA44_PUBKEY_SIZE, 0xcc);
    const std::vector<unsigned char> htlc_leaf = BuildP2MRHTLCLeaf(preimage_hash, PQAlgorithm::ML_DSA_44, oracle_key.GetPubKey());
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

BOOST_AUTO_TEST_SUITE_END()
