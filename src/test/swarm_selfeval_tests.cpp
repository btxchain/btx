// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_selfeval.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_selfeval_tests, BasicTestingSetup)

static modelnet::SwarmSelfEval NotedEval()
{
    modelnet::SwarmSelfEval eval;
    eval.author_id = "author-a";
    eval.evaluator_id = "evaluator-b";
    eval.want_score = false;
    return eval;
}

BOOST_AUTO_TEST_CASE(empty_author_id_is_author)
{
    modelnet::SwarmSelfEval eval = NotedEval();
    eval.author_id.clear();
    std::string err = "prior";
    const modelnet::SwarmSelfEvalResult result = modelnet::SwarmNoteSelfEval(eval, err);
    BOOST_CHECK(!result.scored);
    BOOST_CHECK_EQUAL(result.code, "AUTHOR");
    BOOST_CHECK_EQUAL(err, "AUTHOR");
}

BOOST_AUTO_TEST_CASE(empty_evaluator_id_is_author)
{
    modelnet::SwarmSelfEval eval = NotedEval();
    eval.evaluator_id.clear();
    std::string err = "prior";
    const modelnet::SwarmSelfEvalResult result = modelnet::SwarmNoteSelfEval(eval, err);
    BOOST_CHECK(!result.scored);
    BOOST_CHECK_EQUAL(result.code, "AUTHOR");
    BOOST_CHECK_EQUAL(err, "AUTHOR");
}

BOOST_AUTO_TEST_CASE(empty_ids_win_over_self_and_want_score)
{
    modelnet::SwarmSelfEval eval = NotedEval();
    eval.author_id.clear();
    eval.evaluator_id.clear();
    eval.want_score = true;
    std::string err = "prior";
    const modelnet::SwarmSelfEvalResult result = modelnet::SwarmNoteSelfEval(eval, err);
    BOOST_CHECK(!result.scored);
    BOOST_CHECK_EQUAL(result.code, "AUTHOR");
    BOOST_CHECK_EQUAL(err, "AUTHOR");
}

BOOST_AUTO_TEST_CASE(author_cannot_evaluate_self_even_when_want_score)
{
    modelnet::SwarmSelfEval eval = NotedEval();
    eval.evaluator_id = eval.author_id;
    eval.want_score = true;
    std::string err = "prior";
    const modelnet::SwarmSelfEvalResult result = modelnet::SwarmNoteSelfEval(eval, err);
    BOOST_CHECK(!result.scored);
    BOOST_CHECK_EQUAL(result.code, "SELF");
    BOOST_CHECK_EQUAL(err, "SELF");
}

BOOST_AUTO_TEST_CASE(want_score_is_held_and_does_not_score)
{
    modelnet::SwarmSelfEval eval = NotedEval();
    eval.want_score = true;
    std::string err = "prior";
    const modelnet::SwarmSelfEvalResult result = modelnet::SwarmNoteSelfEval(eval, err);
    BOOST_CHECK(!result.scored);
    BOOST_CHECK_EQUAL(result.code, "HELD");
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_CASE(distinct_ids_are_noted_and_do_not_score)
{
    modelnet::SwarmSelfEval eval = NotedEval();
    std::string err = "prior";
    const modelnet::SwarmSelfEvalResult result = modelnet::SwarmNoteSelfEval(eval, err);
    BOOST_CHECK(!result.scored);
    BOOST_CHECK_EQUAL(result.code, "NOTED");
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_SUITE_END()
