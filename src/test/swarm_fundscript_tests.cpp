// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_fundscript.h>
#include <pqkey.h>
#include <script/interpreter.h>
#include <script/pqm.h>
#include <script/script.h>
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

std::vector<unsigned char> Key(unsigned char fill)
{
    return std::vector<unsigned char>(MLDSA44_PUBKEY_SIZE, fill);
}

std::vector<unsigned char> SizedSig()
{
    return std::vector<unsigned char>(MLDSA44_SIGNATURE_SIZE, 0x01);
}

CScript P2MRProgram(const std::vector<unsigned char>& leaf)
{
    const uint256 leaf_hash = ComputeP2MRLeafHash(P2MR_LEAF_VERSION, leaf);
    const uint256 root = ComputeP2MRMerkleRoot({leaf_hash});
    CScript script_pubkey;
    script_pubkey << OP_2 << std::vector<unsigned char>(root.begin(), root.end());
    return script_pubkey;
}

//! Witness is the supplied items, then the leaf, then a single-leaf control block.
bool RunLeaf(const std::vector<unsigned char>& leaf,
             const std::vector<std::vector<unsigned char>>& witness_items,
             bool locktime_ok,
             ScriptError& err)
{
    CScriptWitness witness;
    for (const std::vector<unsigned char>& item : witness_items) {
        witness.stack.push_back(item);
    }
    witness.stack.push_back(leaf);
    witness.stack.push_back({P2MR_LEAF_VERSION});
    constexpr unsigned int flags = SCRIPT_VERIFY_P2SH | SCRIPT_VERIFY_WITNESS |
                                   SCRIPT_VERIFY_CHECKLOCKTIMEVERIFY | SCRIPT_VERIFY_NULLFAIL;
    const P2MRTemplateChecker checker{locktime_ok};
    return VerifyScript(CScript{}, P2MRProgram(leaf), &witness, flags, checker, &err);
}

} // namespace

BOOST_FIXTURE_TEST_SUITE(swarm_fundscript_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(empty_or_unbound_template_is_refused)
{
    modelnet::SwarmFundScript script;
    std::string err;

    BOOST_CHECK(!modelnet::SwarmAssembleFundScript({}, {}, 500, script, err));
    BOOST_CHECK_EQUAL(err, "FUNDING_SCRIPT");
    BOOST_CHECK(!script.bound);
    BOOST_CHECK(script.funding_script.empty());
    BOOST_CHECK(script.refund_script.empty());

    BOOST_CHECK(!modelnet::SwarmAssembleFundScript(Key(0x11), Key(0x11), 500, script, err));
    BOOST_CHECK_EQUAL(err, "FUNDING_SCRIPT");
    BOOST_CHECK(!script.bound);

    BOOST_CHECK(!modelnet::SwarmAssembleFundScript(Key(0x11), Key(0x22), 0, script, err));
    BOOST_CHECK_EQUAL(err, "REFUND_UNBOUND");
    BOOST_CHECK(!script.bound);
    BOOST_CHECK(script.funding_script.empty());
    BOOST_CHECK(script.refund_script.empty());
}

BOOST_AUTO_TEST_CASE(bound_template_verifies_for_matching_witness)
{
    const std::vector<unsigned char> sponsor = Key(0x11);
    const std::vector<unsigned char> worker = Key(0x22);
    constexpr int64_t refund_height{500};

    modelnet::SwarmFundScript script;
    std::string err;
    BOOST_REQUIRE(modelnet::SwarmAssembleFundScript(sponsor, worker, refund_height, script, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK(script.bound);
    BOOST_CHECK(script.funding_script == BuildP2MRMultisigScript(
                    2, {{PQAlgorithm::ML_DSA_44, sponsor}, {PQAlgorithm::ML_DSA_44, worker}}));
    BOOST_CHECK(script.refund_script == BuildP2MRRefundLeaf(refund_height, PQAlgorithm::ML_DSA_44, sponsor));

    ScriptError funding_err{SCRIPT_ERR_UNKNOWN_ERROR};
    const bool funding_ok = RunLeaf(script.funding_script, {SizedSig(), SizedSig()}, /*locktime_ok=*/true, funding_err);
    BOOST_CHECK_MESSAGE(funding_ok, ScriptErrorString(funding_err));
    BOOST_CHECK_EQUAL(funding_err, SCRIPT_ERR_OK);

    ScriptError refund_err{SCRIPT_ERR_UNKNOWN_ERROR};
    const bool refund_ok = RunLeaf(script.refund_script, {SizedSig()}, /*locktime_ok=*/true, refund_err);
    BOOST_CHECK_MESSAGE(refund_ok, ScriptErrorString(refund_err));
    BOOST_CHECK_EQUAL(refund_err, SCRIPT_ERR_OK);
}

BOOST_AUTO_TEST_CASE(bound_template_rejects_unsatisfied_witness)
{
    modelnet::SwarmFundScript script;
    std::string err;
    BOOST_REQUIRE(modelnet::SwarmAssembleFundScript(Key(0x11), Key(0x22), 500, script, err));
    BOOST_REQUIRE(script.bound);

    ScriptError funding_err{SCRIPT_ERR_OK};
    const bool funding_ok = RunLeaf(script.funding_script, {{}, SizedSig()}, /*locktime_ok=*/true, funding_err);
    BOOST_CHECK(!funding_ok);
    BOOST_CHECK_EQUAL(funding_err, SCRIPT_ERR_EVAL_FALSE);

    ScriptError refund_err{SCRIPT_ERR_OK};
    const bool refund_ok = RunLeaf(script.refund_script, {SizedSig()}, /*locktime_ok=*/false, refund_err);
    BOOST_CHECK(!refund_ok);
    BOOST_CHECK_EQUAL(refund_err, SCRIPT_ERR_UNSATISFIED_LOCKTIME);
}

BOOST_AUTO_TEST_SUITE_END()
