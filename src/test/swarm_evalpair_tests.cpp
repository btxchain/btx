// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_evalpair.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <cstdint>
#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_evalpair_tests, BasicTestingSetup)

static modelnet::SwarmEvalPair NotedPair()
{
    modelnet::SwarmEvalPair pair;
    pair.candidate_id = "cand-1";
    pair.evaluator_a = "eval-a";
    pair.evaluator_b = "eval-b";
    pair.domain_a = "domain-a";
    pair.domain_b = "domain-b";
    pair.outcomes_agree = true;
    pair.want_settle = false;
    return pair;
}

BOOST_AUTO_TEST_CASE(empty_candidate_id_is_eval)
{
    modelnet::SwarmEvalPair pair = NotedPair();
    pair.candidate_id.clear();
    std::string err = "prior";
    const modelnet::SwarmEvalPairResult result = modelnet::SwarmNoteEvalPair(pair, err);
    BOOST_CHECK(!result.settled);
    BOOST_CHECK_EQUAL(result.code, "EVAL");
    BOOST_CHECK_EQUAL(err, "EVAL");
}

BOOST_AUTO_TEST_CASE(empty_evaluator_a_is_eval)
{
    modelnet::SwarmEvalPair pair = NotedPair();
    pair.evaluator_a.clear();
    std::string err = "prior";
    const modelnet::SwarmEvalPairResult result = modelnet::SwarmNoteEvalPair(pair, err);
    BOOST_CHECK(!result.settled);
    BOOST_CHECK_EQUAL(result.code, "EVAL");
    BOOST_CHECK_EQUAL(err, "EVAL");
}

BOOST_AUTO_TEST_CASE(empty_evaluator_b_is_eval)
{
    modelnet::SwarmEvalPair pair = NotedPair();
    pair.evaluator_b.clear();
    std::string err = "prior";
    const modelnet::SwarmEvalPairResult result = modelnet::SwarmNoteEvalPair(pair, err);
    BOOST_CHECK(!result.settled);
    BOOST_CHECK_EQUAL(result.code, "EVAL");
    BOOST_CHECK_EQUAL(err, "EVAL");
}

BOOST_AUTO_TEST_CASE(empty_domain_a_is_eval)
{
    modelnet::SwarmEvalPair pair = NotedPair();
    pair.domain_a.clear();
    std::string err = "prior";
    const modelnet::SwarmEvalPairResult result = modelnet::SwarmNoteEvalPair(pair, err);
    BOOST_CHECK(!result.settled);
    BOOST_CHECK_EQUAL(result.code, "EVAL");
    BOOST_CHECK_EQUAL(err, "EVAL");
}

BOOST_AUTO_TEST_CASE(empty_domain_b_is_eval)
{
    modelnet::SwarmEvalPair pair = NotedPair();
    pair.domain_b.clear();
    std::string err = "prior";
    const modelnet::SwarmEvalPairResult result = modelnet::SwarmNoteEvalPair(pair, err);
    BOOST_CHECK(!result.settled);
    BOOST_CHECK_EQUAL(result.code, "EVAL");
    BOOST_CHECK_EQUAL(err, "EVAL");
}

BOOST_AUTO_TEST_CASE(empty_fields_win_over_same_evaluator_domain_and_settle)
{
    modelnet::SwarmEvalPair pair = NotedPair();
    pair.candidate_id.clear();
    pair.evaluator_b = pair.evaluator_a;
    pair.domain_b = pair.domain_a;
    pair.outcomes_agree = true;
    pair.want_settle = true;
    std::string err = "prior";
    const modelnet::SwarmEvalPairResult result = modelnet::SwarmNoteEvalPair(pair, err);
    BOOST_CHECK(!result.settled);
    BOOST_CHECK_EQUAL(result.code, "EVAL");
    BOOST_CHECK_EQUAL(err, "EVAL");
}

BOOST_AUTO_TEST_CASE(same_evaluator_wins_when_domains_differ_and_want_settle)
{
    modelnet::SwarmEvalPair pair = NotedPair();
    pair.evaluator_b = pair.evaluator_a;
    pair.outcomes_agree = true;
    pair.want_settle = true;
    std::string err = "prior";
    const modelnet::SwarmEvalPairResult result = modelnet::SwarmNoteEvalPair(pair, err);
    BOOST_CHECK(!result.settled);
    BOOST_CHECK_EQUAL(result.code, "SAME_EVALUATOR");
    BOOST_CHECK_EQUAL(err, "SAME_EVALUATOR");
    BOOST_CHECK(pair.domain_a != pair.domain_b);
}

BOOST_AUTO_TEST_CASE(same_domain_wins_when_outcomes_agree_and_want_settle)
{
    modelnet::SwarmEvalPair pair = NotedPair();
    pair.domain_b = pair.domain_a;
    pair.outcomes_agree = true;
    pair.want_settle = true;
    std::string err = "prior";
    const modelnet::SwarmEvalPairResult result = modelnet::SwarmNoteEvalPair(pair, err);
    BOOST_CHECK(!result.settled);
    BOOST_CHECK_EQUAL(result.code, "SAME_DOMAIN");
    BOOST_CHECK_EQUAL(err, "SAME_DOMAIN");
    BOOST_CHECK(pair.evaluator_a != pair.evaluator_b);
}

BOOST_AUTO_TEST_CASE(disagreement_is_split)
{
    modelnet::SwarmEvalPair pair = NotedPair();
    pair.outcomes_agree = false;
    std::string err = "prior";
    const modelnet::SwarmEvalPairResult result = modelnet::SwarmNoteEvalPair(pair, err);
    BOOST_CHECK(!result.settled);
    BOOST_CHECK_EQUAL(result.code, "SPLIT");
    BOOST_CHECK_EQUAL(err, "SPLIT");
}

BOOST_AUTO_TEST_CASE(disagreement_wins_over_want_settle)
{
    modelnet::SwarmEvalPair pair = NotedPair();
    pair.outcomes_agree = false;
    pair.want_settle = true;
    std::string err = "prior";
    const modelnet::SwarmEvalPairResult result = modelnet::SwarmNoteEvalPair(pair, err);
    BOOST_CHECK(!result.settled);
    BOOST_CHECK_EQUAL(result.code, "SPLIT");
    BOOST_CHECK_EQUAL(err, "SPLIT");
}

BOOST_AUTO_TEST_CASE(want_settle_is_held)
{
    modelnet::SwarmEvalPair pair = NotedPair();
    pair.outcomes_agree = true;
    pair.want_settle = true;
    std::string err = "prior";
    const modelnet::SwarmEvalPairResult result = modelnet::SwarmNoteEvalPair(pair, err);
    BOOST_CHECK(!result.settled);
    BOOST_CHECK_EQUAL(result.code, "HELD");
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_CASE(distinct_agreeing_pair_is_noted_and_unsettled)
{
    modelnet::SwarmEvalPair pair = NotedPair();
    pair.outcomes_agree = true;
    pair.want_settle = false;
    std::string err = "prior";
    const modelnet::SwarmEvalPairResult result = modelnet::SwarmNoteEvalPair(pair, err);
    BOOST_CHECK(!result.settled);
    BOOST_CHECK_EQUAL(result.code, "NOTED");
    BOOST_CHECK(err.empty());
    BOOST_CHECK(pair.evaluator_a != pair.evaluator_b);
    BOOST_CHECK(pair.domain_a != pair.domain_b);
}

BOOST_AUTO_TEST_SUITE_END()
