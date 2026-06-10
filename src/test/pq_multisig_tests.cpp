// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <pqkey.h>
#include <script/interpreter.h>
#include <script/pqm.h>
#include <script/script.h>
#include <script/script_error.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <vector>

namespace {

class AlwaysTruePQChecker final : public BaseSignatureChecker
{
public:
    bool CheckPQSignature(Span<const unsigned char>, Span<const unsigned char>, PQAlgorithm, uint8_t, SigVersion, ScriptExecutionData&, bool) const override
    {
        return true;
    }
};

bool EvalP2MR(CScript script, std::vector<std::vector<unsigned char>>& stack, ScriptExecutionData& execdata, ScriptError& serror)
{
    const unsigned int flags = SCRIPT_VERIFY_NULLFAIL;
    return EvalScript(stack, script, flags, AlwaysTruePQChecker{}, SigVersion::P2MR, execdata, &serror);
}

} // namespace

BOOST_FIXTURE_TEST_SUITE(pq_multisig_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(checksigadd_empty_sig_keeps_counter_and_weight)
{
    std::vector<unsigned char> pubkey(MLDSA44_PUBKEY_SIZE, 0x11);
    CScript script;
    script << pubkey << OP_CHECKSIGADD_MLDSA;

    std::vector<std::vector<unsigned char>> stack;
    stack.push_back({}); // empty signature
    stack.push_back(CScriptNum{7}.getvch());

    ScriptExecutionData execdata;
    execdata.m_validation_weight_left_init = true;
    execdata.m_validation_weight_left = 1000;
    const int64_t weight_before = execdata.m_validation_weight_left;

    ScriptError serror = SCRIPT_ERR_OK;
    BOOST_REQUIRE(EvalP2MR(script, stack, execdata, serror));
    BOOST_CHECK_EQUAL(serror, SCRIPT_ERR_OK);
    BOOST_REQUIRE_EQUAL(stack.size(), 1U);
    const int64_t n_after = CScriptNum(stack.back(), /*fRequireMinimal=*/true).GetInt64();
    BOOST_CHECK_EQUAL(n_after, 7);
    BOOST_CHECK_EQUAL(execdata.m_validation_weight_left, weight_before);
}

BOOST_AUTO_TEST_CASE(checksigadd_nonempty_sig_increments_counter_and_debits_weight)
{
    std::vector<unsigned char> pubkey(MLDSA44_PUBKEY_SIZE, 0x22);
    CScript script;
    script << pubkey << OP_CHECKSIGADD_MLDSA;

    std::vector<std::vector<unsigned char>> stack;
    stack.push_back(std::vector<unsigned char>(MLDSA44_SIGNATURE_SIZE, 0x33));
    stack.push_back(CScriptNum{4}.getvch());

    ScriptExecutionData execdata;
    execdata.m_validation_weight_left_init = true;
    execdata.m_validation_weight_left = 2000;

    ScriptError serror = SCRIPT_ERR_OK;
    BOOST_REQUIRE(EvalP2MR(script, stack, execdata, serror));
    BOOST_CHECK_EQUAL(serror, SCRIPT_ERR_OK);
    BOOST_REQUIRE_EQUAL(stack.size(), 1U);
    const int64_t n_after = CScriptNum(stack.back(), /*fRequireMinimal=*/true).GetInt64();
    BOOST_CHECK_EQUAL(n_after, 5);
    BOOST_CHECK_EQUAL(execdata.m_validation_weight_left, 2000 - VALIDATION_WEIGHT_PER_MLDSA_MULTISIG_SIGOP);
}

BOOST_AUTO_TEST_CASE(checksigadd_validation_weight_exhaustion_fails)
{
    std::vector<unsigned char> pubkey(MLDSA44_PUBKEY_SIZE, 0x44);
    CScript script;
    script << pubkey << OP_CHECKSIGADD_MLDSA;

    std::vector<std::vector<unsigned char>> stack;
    stack.push_back(std::vector<unsigned char>(MLDSA44_SIGNATURE_SIZE, 0x55));
    stack.push_back(CScriptNum{1}.getvch());

    ScriptExecutionData execdata;
    execdata.m_validation_weight_left_init = true;
    execdata.m_validation_weight_left = VALIDATION_WEIGHT_PER_MLDSA_MULTISIG_SIGOP - 1;

    ScriptError serror = SCRIPT_ERR_OK;
    BOOST_CHECK(!EvalP2MR(script, stack, execdata, serror));
    BOOST_CHECK_EQUAL(serror, SCRIPT_ERR_TAPSCRIPT_VALIDATION_WEIGHT);
}

BOOST_AUTO_TEST_CASE(checksigadd_rejects_wrong_pubkey_size)
{
    CScript script;
    script << std::vector<unsigned char>{0x01} << OP_CHECKSIGADD_MLDSA;

    std::vector<std::vector<unsigned char>> stack;
    stack.push_back(std::vector<unsigned char>(MLDSA44_SIGNATURE_SIZE, 0x66));
    stack.push_back(CScriptNum{0}.getvch());

    ScriptExecutionData execdata;
    execdata.m_validation_weight_left_init = true;
    execdata.m_validation_weight_left = 1000;

    ScriptError serror = SCRIPT_ERR_OK;
    BOOST_CHECK(!EvalP2MR(script, stack, execdata, serror));
    BOOST_CHECK_EQUAL(serror, SCRIPT_ERR_PQ_PUBKEY_SIZE);
}

BOOST_AUTO_TEST_CASE(build_p2mr_multisig_script_enforces_limits_and_mixed_algorithms)
{
    const std::vector<unsigned char> mldsa_pk_a(MLDSA44_PUBKEY_SIZE, 0x10);
    const std::vector<unsigned char> mldsa_pk_b(MLDSA44_PUBKEY_SIZE, 0x20);
    const std::vector<unsigned char> slh_pk(SLHDSA128S_PUBKEY_SIZE, 0x30);

    BOOST_CHECK(BuildP2MRMultisigScript(/*threshold=*/0, {{PQAlgorithm::ML_DSA_44, mldsa_pk_a}}).empty());
    BOOST_CHECK(BuildP2MRMultisigScript(/*threshold=*/1, {{PQAlgorithm::ML_DSA_44, mldsa_pk_a}}).empty());
    BOOST_CHECK(BuildP2MRMultisigScript(/*threshold=*/2, {{PQAlgorithm::ML_DSA_44, mldsa_pk_a}}).empty());

    std::vector<std::pair<PQAlgorithm, std::vector<unsigned char>>> too_many;
    for (unsigned int i = 0; i < MAX_PQ_PUBKEYS_PER_MULTISIG + 1; ++i) {
        too_many.push_back({PQAlgorithm::SLH_DSA_128S, std::vector<unsigned char>(SLHDSA128S_PUBKEY_SIZE, static_cast<unsigned char>(i))});
    }
    BOOST_CHECK(BuildP2MRMultisigScript(/*threshold=*/2, too_many).empty());
    BOOST_CHECK(BuildP2MRMultisigScript(
        /*threshold=*/2,
        {
            {PQAlgorithm::ML_DSA_44, mldsa_pk_a},
            {PQAlgorithm::ML_DSA_44, mldsa_pk_a},
            {PQAlgorithm::SLH_DSA_128S, slh_pk},
        }).empty());

    // 8-of-8 ML-DSA now fits within MAX_P2MR_SCRIPT_SIZE (11000 bytes).
    std::vector<std::pair<PQAlgorithm, std::vector<unsigned char>>> max_mldsa_leaf;
    max_mldsa_leaf.reserve(MAX_PQ_PUBKEYS_PER_MULTISIG);
    for (unsigned int i = 0; i < MAX_PQ_PUBKEYS_PER_MULTISIG; ++i) {
        max_mldsa_leaf.push_back({PQAlgorithm::ML_DSA_44, std::vector<unsigned char>(MLDSA44_PUBKEY_SIZE, static_cast<unsigned char>(0x80 + i))});
    }
    BOOST_CHECK(!BuildP2MRMultisigScript(/*threshold=*/2, max_mldsa_leaf).empty());

    const std::vector<unsigned char> script = BuildP2MRMultisigScript(
        /*threshold=*/2,
        {
            {PQAlgorithm::ML_DSA_44, mldsa_pk_a},
            {PQAlgorithm::ML_DSA_44, mldsa_pk_b},
            {PQAlgorithm::SLH_DSA_128S, slh_pk},
        });
    BOOST_REQUIRE(!script.empty());

    CScript expected;
    expected << mldsa_pk_a << OP_CHECKSIG_MLDSA
             << mldsa_pk_b << OP_CHECKSIGADD_MLDSA
             << slh_pk << OP_CHECKSIGADD_SLHDSA
             << 2 << OP_NUMEQUAL;
    BOOST_CHECK_EQUAL_COLLECTIONS(script.begin(), script.end(), expected.begin(), expected.end());
}

// ---------------------------------------------------------------------------
// EVX Babylon-style covenant demonstration (issue #248 / doc/btx-op-check-multi-pq-plan.md).
// These prove that a k-of-n ML-DSA/SLH-DSA covenant "quorum" is expressible TODAY with the existing
// P2MR opcodes -- so BTX needs no new OP_CHECK_MULTI_PQ consensus opcode for committees that fit the
// consensus leaf-size limit, and pins the exact boundary where it would.
// ---------------------------------------------------------------------------
namespace {
// Build a k-of-n PQ multisig leaf in the same shape as BuildP2MRMultisigScript, but manually so we can
// exercise committee sizes beyond the relay-policy cap (MAX_PQ_PUBKEYS_PER_MULTISIG) to observe the
// consensus leaf-size boundary (MAX_P2MR_SCRIPT_SIZE).
CScript BuildKofNLeaf(PQAlgorithm algo, unsigned n, unsigned k, size_t pubkey_size)
{
    CScript s;
    for (unsigned i = 0; i < n; ++i) {
        const std::vector<unsigned char> pk(pubkey_size, static_cast<unsigned char>(0x10 + i));
        s << pk;
        s << (i == 0 ? GetP2MRChecksigOpcode(algo) : GetP2MRChecksigAddOpcode(algo));
    }
    s << static_cast<int64_t>(k) << OP_NUMEQUAL;
    return s;
}
} // namespace

BOOST_AUTO_TEST_CASE(covenant_kofn_committee_size_boundary)
{
    // ML-DSA committee of 8 fits the consensus leaf-size limit -> k-of-n covenant works TODAY.
    const CScript mldsa8 = BuildKofNLeaf(PQAlgorithm::ML_DSA_44, 8, 5, MLDSA44_PUBKEY_SIZE);
    BOOST_CHECK_LE(mldsa8.size(), MAX_P2MR_SCRIPT_SIZE);

    // ML-DSA committee of 9 (e.g. Babylon-typical 6-of-9) EXCEEDS the consensus leaf-size limit.
    // This is the ONLY case that would require a BTX consensus change (Path B in the plan) -- and it
    // is avoidable by using SLH-DSA committee keys (below).
    const CScript mldsa9 = BuildKofNLeaf(PQAlgorithm::ML_DSA_44, 9, 6, MLDSA44_PUBKEY_SIZE);
    BOOST_CHECK_GT(mldsa9.size(), MAX_P2MR_SCRIPT_SIZE);

    // SLH-DSA-128s committee of 16 (32-byte pubkeys) fits easily -> any realistic committee works
    // TODAY with the small-pubkey algorithm, no BTX consensus change.
    const CScript slhdsa16 = BuildKofNLeaf(PQAlgorithm::SLH_DSA_128S, 16, 6, SLHDSA128S_PUBKEY_SIZE);
    BOOST_CHECK_LE(slhdsa16.size(), MAX_P2MR_SCRIPT_SIZE);
}

BOOST_AUTO_TEST_CASE(covenant_kofn_mldsa_threshold_logic)
{
    // 5-of-8 ML-DSA covenant quorum, built from the existing P2MR accumulator opcodes.
    const CScript leaf = BuildKofNLeaf(PQAlgorithm::ML_DSA_44, 8, 5, MLDSA44_PUBKEY_SIZE);
    BOOST_REQUIRE_LE(leaf.size(), MAX_P2MR_SCRIPT_SIZE);

    // Evaluate with `num_sigs` correctly-sized signatures and (8 - num_sigs) empty (non-signer) slots.
    // With the AlwaysTrue checker every non-empty sig verifies, so the accumulator counts num_sigs and
    // the trailing `<5> OP_NUMEQUAL` returns true iff exactly the threshold signed.
    auto satisfied = [&](unsigned num_sigs) {
        std::vector<std::vector<unsigned char>> stack;
        for (unsigned i = 0; i < 8; ++i) {
            if (i < 8 - num_sigs) {
                stack.push_back({}); // non-signer
            } else {
                stack.push_back(std::vector<unsigned char>(MLDSA44_SIGNATURE_SIZE, 0x33));
            }
        }
        ScriptExecutionData execdata;
        execdata.m_validation_weight_left_init = true;
        execdata.m_validation_weight_left = 1'000'000;
        ScriptError serror = SCRIPT_ERR_OK;
        BOOST_REQUIRE(EvalP2MR(leaf, stack, execdata, serror));
        BOOST_CHECK_EQUAL(serror, SCRIPT_ERR_OK);
        BOOST_REQUIRE_EQUAL(stack.size(), 1U);
        return !stack.back().empty(); // OP_NUMEQUAL pushes {0x01} for true, {} for false
    };

    BOOST_CHECK(satisfied(5));   // exactly the threshold -> covenant quorum satisfied
    BOOST_CHECK(!satisfied(4));  // below threshold -> not satisfied
}

BOOST_AUTO_TEST_SUITE_END()
