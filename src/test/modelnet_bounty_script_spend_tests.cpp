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

    bool CheckPQSignature(Span<const unsigned char> sig, Span<const unsigned char>, PQAlgorithm, uint8_t, SigVersion, ScriptExecutionData&, bool) const override
    {
        return sig.size() == MLDSA44_SIGNATURE_SIZE;
    }

    bool CheckLockTime(const CScriptNum&) const override { return m_locktime_ok; }

private:
    bool m_locktime_ok;
};

std::vector<unsigned char> DummyPubkey(unsigned char seed)
{
    return std::vector<unsigned char>(MLDSA44_PUBKEY_SIZE, seed);
}

std::vector<unsigned char> Sha256Bytes(Span<const unsigned char> data)
{
    uint256 hash;
    CSHA256().Write(data.data(), data.size()).Finalize(hash.begin());
    return {hash.begin(), hash.end()};
}

bool EvalP2MRScript(const CScript& script, std::vector<std::vector<unsigned char>>& stack, const BaseSignatureChecker& checker,
                    ScriptExecutionData& execdata, ScriptError& serror)
{
    constexpr unsigned int flags = SCRIPT_VERIFY_NULLFAIL | SCRIPT_VERIFY_CHECKLOCKTIMEVERIFY;
    return EvalScript(stack, script, flags, checker, SigVersion::P2MR, execdata, &serror);
}

void InitExec(ScriptExecutionData& execdata)
{
    execdata.m_validation_weight_left_init = true;
    execdata.m_validation_weight_left = 5000;
}

std::vector<std::pair<PQAlgorithm, std::vector<unsigned char>>> CouncilKeys(int count, unsigned char seed)
{
    std::vector<std::pair<PQAlgorithm, std::vector<unsigned char>>> keys;
    keys.reserve(static_cast<size_t>(count));
    for (int i = 0; i < count; ++i) {
        keys.push_back({PQAlgorithm::ML_DSA_44, DummyPubkey(static_cast<unsigned char>(seed + i))});
    }
    return keys;
}

void PushThresholdSigs(std::vector<std::vector<unsigned char>>& stack, int nonempty_count, int key_count)
{
    for (int i = 0; i < key_count; ++i) {
        if (i < key_count - nonempty_count) {
            stack.push_back({});
        } else {
            stack.push_back(std::vector<unsigned char>(MLDSA44_SIGNATURE_SIZE, 0x01));
        }
    }
}

} // namespace

BOOST_FIXTURE_TEST_SUITE(modelnet_bounty_script_spend_tests, BasicTestingSetup)

// BOUNTY-SCRIPT-005 — award CLTV before vs at earliest award height (interpreter CheckLockTime gate).
// BOUNTY-SCRIPT-006 — refund CLTV before vs at maturity.
// BOUNTY-SCRIPT-007 — after refund height refund leaf can succeed; award leaf still requires council sigs.
BOOST_AUTO_TEST_CASE(bounty_script_005_006_007_cltv_leaf_eval)
{
    constexpr int64_t kAwardHeight = 400;
    constexpr int64_t kRefundHeight = 600;
    constexpr uint8_t kThreshold = 3;
    const auto council = CouncilKeys(3, 0x10);
    const std::vector<unsigned char> refund_pk = DummyPubkey(0x90);

    const std::vector<unsigned char> award_bytes =
        BuildP2MRCLTVMultisigScript(kAwardHeight, kThreshold, council);
    const std::vector<unsigned char> refund_bytes =
        BuildP2MRRefundLeaf(kRefundHeight, PQAlgorithm::ML_DSA_44, refund_pk);
    BOOST_REQUIRE(!award_bytes.empty());
    BOOST_REQUIRE(!refund_bytes.empty());
    const CScript award_script{award_bytes.begin(), award_bytes.end()};
    const CScript refund_script{refund_bytes.begin(), refund_bytes.end()};

    // SCRIPT-005: award leaf rejects when locktime not satisfied.
    {
        std::vector<std::vector<unsigned char>> stack;
        PushThresholdSigs(stack, kThreshold, static_cast<int>(council.size()));
        ScriptExecutionData execdata;
        InitExec(execdata);
        ScriptError serror = SCRIPT_ERR_OK;
        const P2MRTemplateChecker early{/*locktime_ok=*/false};
        BOOST_CHECK(!EvalP2MRScript(award_script, stack, early, execdata, serror));
        BOOST_CHECK_EQUAL(serror, SCRIPT_ERR_UNSATISFIED_LOCKTIME);
    }
    // SCRIPT-005: at award height CLTV passes when threshold signatures are present.
    {
        std::vector<std::vector<unsigned char>> stack;
        PushThresholdSigs(stack, kThreshold, static_cast<int>(council.size()));
        ScriptExecutionData execdata;
        InitExec(execdata);
        ScriptError serror = SCRIPT_ERR_OK;
        const P2MRTemplateChecker at_award{/*locktime_ok=*/true};
        BOOST_REQUIRE(EvalP2MRScript(award_script, stack, at_award, execdata, serror));
        BOOST_CHECK_EQUAL(serror, SCRIPT_ERR_OK);
        BOOST_REQUIRE_EQUAL(stack.size(), 1U);
        BOOST_CHECK_EQUAL(CScriptNum(stack.back(), /*fRequireMinimal=*/true).GetInt64(), 1);
    }

    // SCRIPT-006: refund before maturity fails CLTV.
    {
        std::vector<std::vector<unsigned char>> stack;
        stack.push_back(std::vector<unsigned char>(MLDSA44_SIGNATURE_SIZE, 0x01));
        ScriptExecutionData execdata;
        InitExec(execdata);
        ScriptError serror = SCRIPT_ERR_OK;
        const P2MRTemplateChecker before_refund{/*locktime_ok=*/false};
        BOOST_CHECK(!EvalP2MRScript(refund_script, stack, before_refund, execdata, serror));
        BOOST_CHECK_EQUAL(serror, SCRIPT_ERR_UNSATISFIED_LOCKTIME);
    }
    // SCRIPT-006: refund at maturity with contributor signature path succeeds.
    {
        std::vector<std::vector<unsigned char>> stack;
        stack.push_back(std::vector<unsigned char>(MLDSA44_SIGNATURE_SIZE, 0x01));
        ScriptExecutionData execdata;
        InitExec(execdata);
        ScriptError serror = SCRIPT_ERR_OK;
        const P2MRTemplateChecker at_refund{/*locktime_ok=*/true};
        BOOST_REQUIRE(EvalP2MRScript(refund_script, stack, at_refund, execdata, serror));
        BOOST_CHECK_EQUAL(serror, SCRIPT_ERR_OK);
    }

    // SCRIPT-007: same post-refund height — refund spend ok, award still needs full quorum.
    {
        std::vector<std::vector<unsigned char>> stack;
        stack.push_back(std::vector<unsigned char>(MLDSA44_SIGNATURE_SIZE, 0x01));
        ScriptExecutionData execdata;
        InitExec(execdata);
        ScriptError serror = SCRIPT_ERR_OK;
        const P2MRTemplateChecker after_refund{/*locktime_ok=*/true};
        BOOST_REQUIRE(EvalP2MRScript(refund_script, stack, after_refund, execdata, serror));
    }
    {
        std::vector<std::vector<unsigned char>> stack;
        PushThresholdSigs(stack, /*nonempty_count=*/2, static_cast<int>(council.size()));
        ScriptExecutionData execdata;
        InitExec(execdata);
        ScriptError serror = SCRIPT_ERR_OK;
        const P2MRTemplateChecker after_refund{/*locktime_ok=*/true};
        // OP_NUMEQUAL leaves 0 on the stack rather than aborting; the witness
        // cleanstack/truthy check is what fails the spend (SCRIPT-007).
        BOOST_REQUIRE(EvalP2MRScript(award_script, stack, after_refund, execdata, serror));
        BOOST_CHECK_EQUAL(serror, SCRIPT_ERR_OK);
        BOOST_REQUIRE_EQUAL(stack.size(), 1U);
        BOOST_CHECK_EQUAL(CScriptNum(stack.back(), /*fRequireMinimal=*/true).GetInt64(), 0);
    }
}

// BOUNTY-SCRIPT-019 — staged HTLC leaf: wrong preimage fails; correct preimage + dummy sig succeeds.
BOOST_AUTO_TEST_CASE(bounty_script_019_staged_htlc_leaf_eval)
{
    CPQKey claimant;
    claimant.MakeNewKey(PQAlgorithm::ML_DSA_44);
    BOOST_REQUIRE(claimant.IsValid());

    const std::vector<unsigned char> preimage(32, 0x33);
    const std::vector<unsigned char> preimage_hash = Sha256Bytes(preimage);
    const std::vector<unsigned char> script_bytes =
        BuildP2MRHTLCSha256Leaf(preimage_hash, PQAlgorithm::ML_DSA_44, claimant.GetPubKey());
    BOOST_REQUIRE(!script_bytes.empty());
    const CScript script{script_bytes.begin(), script_bytes.end()};

    {
        const std::vector<unsigned char> wrong_preimage(32, 0x44);
        std::vector<std::vector<unsigned char>> stack;
        stack.push_back(std::vector<unsigned char>(MLDSA44_SIGNATURE_SIZE, 0x01));
        stack.push_back(wrong_preimage);
        ScriptExecutionData execdata;
        InitExec(execdata);
        ScriptError serror = SCRIPT_ERR_OK;
        const P2MRTemplateChecker checker{/*locktime_ok=*/true};
        BOOST_CHECK(!EvalP2MRScript(script, stack, checker, execdata, serror));
        BOOST_CHECK_EQUAL(serror, SCRIPT_ERR_EQUALVERIFY);
    }
    {
        std::vector<std::vector<unsigned char>> stack;
        stack.push_back(std::vector<unsigned char>(MLDSA44_SIGNATURE_SIZE, 0x01));
        stack.push_back(preimage);
        ScriptExecutionData execdata;
        InitExec(execdata);
        ScriptError serror = SCRIPT_ERR_OK;
        const P2MRTemplateChecker checker{/*locktime_ok=*/true};
        BOOST_REQUIRE(EvalP2MRScript(script, stack, checker, execdata, serror));
        BOOST_CHECK_EQUAL(serror, SCRIPT_ERR_OK);
        BOOST_REQUIRE_EQUAL(stack.size(), 1U);
        BOOST_CHECK_EQUAL(CScriptNum(stack.back(), /*fRequireMinimal=*/true).GetInt64(), 1);
    }
}

BOOST_AUTO_TEST_SUITE_END()
