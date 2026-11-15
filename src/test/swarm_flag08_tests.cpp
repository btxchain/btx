// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_flag08.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_flag08_tests, BasicTestingSetup)

static void CheckNeverAdvanced(const modelnet::SwarmFlag08Result& result)
{
    BOOST_CHECK_EQUAL(result.scored, false);
    BOOST_CHECK_EQUAL(result.passed, false);
    BOOST_CHECK_EQUAL(result.graduated, false);
}

static modelnet::SwarmFlag08 NotedEval()
{
    modelnet::SwarmFlag08 in;
    in.candidate_id = "candidate-a";
    in.evaluator_id = "evaluator-b";
    in.author_id = "author-c";
    in.withheld = true;
    in.failed = false;
    in.want_score = false;
    in.want_pass = false;
    return in;
}

BOOST_AUTO_TEST_CASE(empty_candidate_id_is_candidate)
{
    modelnet::SwarmFlag08 in = NotedEval();
    in.candidate_id.clear();
    in.evaluator_id = in.author_id;
    in.withheld = false;
    in.failed = true;
    in.want_score = true;
    in.want_pass = true;
    std::string err = "prior";
    const modelnet::SwarmFlag08Result result = modelnet::SwarmStageEvaluate(in, err);
    BOOST_CHECK_EQUAL(result.code, "CANDIDATE");
    CheckNeverAdvanced(result);
    BOOST_CHECK_EQUAL(result.retained, false);
    BOOST_CHECK_EQUAL(result.rejected, false);
    BOOST_CHECK_EQUAL(err, "CANDIDATE");
}

BOOST_AUTO_TEST_CASE(empty_evaluator_id_is_candidate)
{
    modelnet::SwarmFlag08 in = NotedEval();
    in.evaluator_id.clear();
    in.withheld = false;
    in.failed = true;
    in.want_score = true;
    in.want_pass = true;
    std::string err = "prior";
    const modelnet::SwarmFlag08Result result = modelnet::SwarmStageEvaluate(in, err);
    BOOST_CHECK_EQUAL(result.code, "CANDIDATE");
    CheckNeverAdvanced(result);
    BOOST_CHECK_EQUAL(result.retained, false);
    BOOST_CHECK_EQUAL(result.rejected, false);
    BOOST_CHECK_EQUAL(err, "CANDIDATE");
}

BOOST_AUTO_TEST_CASE(empty_author_id_is_candidate)
{
    modelnet::SwarmFlag08 in = NotedEval();
    in.author_id.clear();
    in.failed = true;
    in.want_score = true;
    in.want_pass = true;
    std::string err = "prior";
    const modelnet::SwarmFlag08Result result = modelnet::SwarmStageEvaluate(in, err);
    BOOST_CHECK_EQUAL(result.code, "CANDIDATE");
    CheckNeverAdvanced(result);
    BOOST_CHECK_EQUAL(result.retained, false);
    BOOST_CHECK_EQUAL(result.rejected, false);
    BOOST_CHECK_EQUAL(err, "CANDIDATE");
}

BOOST_AUTO_TEST_CASE(empty_evaluator_and_author_stay_candidate)
{
    modelnet::SwarmFlag08 in = NotedEval();
    in.evaluator_id.clear();
    in.author_id.clear();
    in.withheld = false;
    in.failed = true;
    in.want_score = true;
    in.want_pass = true;
    std::string err = "prior";
    const modelnet::SwarmFlag08Result result = modelnet::SwarmStageEvaluate(in, err);
    BOOST_CHECK_EQUAL(result.code, "CANDIDATE");
    CheckNeverAdvanced(result);
    BOOST_CHECK_EQUAL(result.retained, false);
    BOOST_CHECK_EQUAL(result.rejected, false);
    BOOST_CHECK_EQUAL(err, "CANDIDATE");
}

BOOST_AUTO_TEST_CASE(same_evaluator_is_same_evaluator)
{
    modelnet::SwarmFlag08 in = NotedEval();
    in.evaluator_id = in.author_id;
    in.withheld = false;
    in.failed = true;
    in.want_score = true;
    in.want_pass = true;
    std::string err = "prior";
    const modelnet::SwarmFlag08Result result = modelnet::SwarmStageEvaluate(in, err);
    BOOST_CHECK_EQUAL(result.code, "SAME_EVALUATOR");
    CheckNeverAdvanced(result);
    BOOST_CHECK_EQUAL(result.retained, false);
    BOOST_CHECK_EQUAL(result.rejected, false);
    BOOST_CHECK_EQUAL(err, "SAME_EVALUATOR");
}

BOOST_AUTO_TEST_CASE(not_withheld_is_not_withheld)
{
    modelnet::SwarmFlag08 in = NotedEval();
    in.withheld = false;
    in.failed = true;
    in.want_score = true;
    in.want_pass = true;
    std::string err = "prior";
    const modelnet::SwarmFlag08Result result = modelnet::SwarmStageEvaluate(in, err);
    BOOST_CHECK_EQUAL(result.code, "NOT_WITHHELD");
    CheckNeverAdvanced(result);
    BOOST_CHECK_EQUAL(result.retained, false);
    BOOST_CHECK_EQUAL(result.rejected, false);
    BOOST_CHECK_EQUAL(err, "NOT_WITHHELD");
}

BOOST_AUTO_TEST_CASE(failed_is_retained_and_not_graduated)
{
    modelnet::SwarmFlag08 in = NotedEval();
    in.withheld = true;
    in.failed = true;
    in.want_score = true;
    in.want_pass = true;
    std::string err = "prior";
    const modelnet::SwarmFlag08Result result = modelnet::SwarmStageEvaluate(in, err);
    BOOST_CHECK_EQUAL(result.code, "RETAINED");
    BOOST_CHECK_EQUAL(result.retained, true);
    BOOST_CHECK_EQUAL(result.rejected, true);
    CheckNeverAdvanced(result);
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_CASE(want_score_is_not_scored)
{
    modelnet::SwarmFlag08 in = NotedEval();
    in.withheld = true;
    in.failed = false;
    in.want_score = true;
    in.want_pass = true;
    std::string err = "prior";
    const modelnet::SwarmFlag08Result result = modelnet::SwarmStageEvaluate(in, err);
    BOOST_CHECK_EQUAL(result.code, "NOT_SCORED");
    CheckNeverAdvanced(result);
    BOOST_CHECK_EQUAL(result.retained, false);
    BOOST_CHECK_EQUAL(result.rejected, false);
    BOOST_CHECK_EQUAL(err, "NOT_SCORED");
}

BOOST_AUTO_TEST_CASE(want_pass_is_unqualified)
{
    modelnet::SwarmFlag08 in = NotedEval();
    in.withheld = true;
    in.failed = false;
    in.want_score = false;
    in.want_pass = true;
    std::string err = "prior";
    const modelnet::SwarmFlag08Result result = modelnet::SwarmStageEvaluate(in, err);
    BOOST_CHECK_EQUAL(result.code, "UNQUALIFIED");
    CheckNeverAdvanced(result);
    BOOST_CHECK_EQUAL(result.retained, false);
    BOOST_CHECK_EQUAL(result.rejected, false);
    BOOST_CHECK_EQUAL(err, "UNQUALIFIED");
}

BOOST_AUTO_TEST_CASE(withheld_independent_note_is_noted)
{
    modelnet::SwarmFlag08 in = NotedEval();
    std::string err = "prior";
    const modelnet::SwarmFlag08Result result = modelnet::SwarmStageEvaluate(in, err);
    BOOST_CHECK_EQUAL(result.code, "NOTED");
    CheckNeverAdvanced(result);
    BOOST_CHECK_EQUAL(result.retained, false);
    BOOST_CHECK_EQUAL(result.rejected, false);
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_SUITE_END()
