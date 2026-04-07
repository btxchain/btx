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
    bool CheckPQSignature(Span<const unsigned char>, Span<const unsigned char>, PQAlgorithm, uint8_t, SigVersion, ScriptExecutionData&) const override
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

BOOST_AUTO_TEST_SUITE_END()
