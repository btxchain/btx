// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_flag07.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_flag07_tests, BasicTestingSetup)

static modelnet::SwarmFlag07 NotedEvolve()
{
    modelnet::SwarmFlag07 in;
    in.parent_id = "parent-1";
    in.candidate_a = "cand-a";
    in.candidate_b = "cand-b";
    in.different_strategy = true;
    in.from_real_run = true;
    in.want_pass = false;
    return in;
}

static void ExpectNoDescendant(const modelnet::SwarmFlag07Result& result)
{
    BOOST_CHECK(!result.produced);
    BOOST_CHECK(!result.passed);
    BOOST_CHECK(!result.bytes_moved);
}

BOOST_AUTO_TEST_CASE(empty_parent_id_is_parent)
{
    modelnet::SwarmFlag07 in = NotedEvolve();
    in.parent_id.clear();
    std::string err = "prior";
    const modelnet::SwarmFlag07Result result = modelnet::SwarmStageEvolve(in, err);
    ExpectNoDescendant(result);
    BOOST_CHECK_EQUAL(result.code, "PARENT");
    BOOST_CHECK_EQUAL(err, "PARENT");
}

BOOST_AUTO_TEST_CASE(empty_candidate_a_is_parent)
{
    modelnet::SwarmFlag07 in = NotedEvolve();
    in.candidate_a.clear();
    std::string err = "prior";
    const modelnet::SwarmFlag07Result result = modelnet::SwarmStageEvolve(in, err);
    ExpectNoDescendant(result);
    BOOST_CHECK_EQUAL(result.code, "PARENT");
    BOOST_CHECK_EQUAL(err, "PARENT");
}

BOOST_AUTO_TEST_CASE(empty_candidate_b_is_parent)
{
    modelnet::SwarmFlag07 in = NotedEvolve();
    in.candidate_b.clear();
    std::string err = "prior";
    const modelnet::SwarmFlag07Result result = modelnet::SwarmStageEvolve(in, err);
    ExpectNoDescendant(result);
    BOOST_CHECK_EQUAL(result.code, "PARENT");
    BOOST_CHECK_EQUAL(err, "PARENT");
}

BOOST_AUTO_TEST_CASE(empty_parent_wins_over_later_flags)
{
    modelnet::SwarmFlag07 in;
    in.parent_id.clear();
    in.candidate_a.clear();
    in.candidate_b.clear();
    in.different_strategy = false;
    in.from_real_run = false;
    in.want_pass = true;
    std::string err = "prior";
    const modelnet::SwarmFlag07Result result = modelnet::SwarmStageEvolve(in, err);
    ExpectNoDescendant(result);
    BOOST_CHECK_EQUAL(result.code, "PARENT");
    BOOST_CHECK_EQUAL(err, "PARENT");
}

BOOST_AUTO_TEST_CASE(equal_candidates_are_same_candidate)
{
    modelnet::SwarmFlag07 in = NotedEvolve();
    in.candidate_b = in.candidate_a;
    std::string err = "prior";
    const modelnet::SwarmFlag07Result result = modelnet::SwarmStageEvolve(in, err);
    ExpectNoDescendant(result);
    BOOST_CHECK_EQUAL(result.code, "SAME_CANDIDATE");
    BOOST_CHECK_EQUAL(err, "SAME_CANDIDATE");
}

BOOST_AUTO_TEST_CASE(equal_candidates_win_over_strategy_and_pass)
{
    modelnet::SwarmFlag07 in = NotedEvolve();
    in.candidate_a = "same";
    in.candidate_b = "same";
    in.different_strategy = false;
    in.from_real_run = false;
    in.want_pass = true;
    std::string err = "prior";
    const modelnet::SwarmFlag07Result result = modelnet::SwarmStageEvolve(in, err);
    ExpectNoDescendant(result);
    BOOST_CHECK_EQUAL(result.code, "SAME_CANDIDATE");
    BOOST_CHECK_EQUAL(err, "SAME_CANDIDATE");
}

BOOST_AUTO_TEST_CASE(same_strategy_when_not_different)
{
    modelnet::SwarmFlag07 in = NotedEvolve();
    in.different_strategy = false;
    std::string err = "prior";
    const modelnet::SwarmFlag07Result result = modelnet::SwarmStageEvolve(in, err);
    ExpectNoDescendant(result);
    BOOST_CHECK_EQUAL(result.code, "SAME_STRATEGY");
    BOOST_CHECK_EQUAL(err, "SAME_STRATEGY");
}

BOOST_AUTO_TEST_CASE(same_strategy_wins_over_not_evolved_and_want_pass)
{
    modelnet::SwarmFlag07 in = NotedEvolve();
    in.different_strategy = false;
    in.from_real_run = false;
    in.want_pass = true;
    std::string err = "prior";
    const modelnet::SwarmFlag07Result result = modelnet::SwarmStageEvolve(in, err);
    ExpectNoDescendant(result);
    BOOST_CHECK_EQUAL(result.code, "SAME_STRATEGY");
    BOOST_CHECK_EQUAL(err, "SAME_STRATEGY");
}

BOOST_AUTO_TEST_CASE(not_from_real_run_is_not_evolved)
{
    modelnet::SwarmFlag07 in = NotedEvolve();
    in.from_real_run = false;
    in.want_pass = false;
    std::string err = "prior";
    const modelnet::SwarmFlag07Result result = modelnet::SwarmStageEvolve(in, err);
    ExpectNoDescendant(result);
    BOOST_CHECK_EQUAL(result.code, "NOT_EVOLVED");
    BOOST_CHECK_EQUAL(err, "NOT_EVOLVED");
}

BOOST_AUTO_TEST_CASE(not_evolved_even_if_want_pass)
{
    modelnet::SwarmFlag07 in = NotedEvolve();
    in.from_real_run = false;
    in.want_pass = true;
    std::string err = "prior";
    const modelnet::SwarmFlag07Result result = modelnet::SwarmStageEvolve(in, err);
    ExpectNoDescendant(result);
    BOOST_CHECK_EQUAL(result.code, "NOT_EVOLVED");
    BOOST_CHECK_EQUAL(err, "NOT_EVOLVED");
}

BOOST_AUTO_TEST_CASE(want_pass_is_unqualified)
{
    modelnet::SwarmFlag07 in = NotedEvolve();
    in.want_pass = true;
    std::string err = "prior";
    const modelnet::SwarmFlag07Result result = modelnet::SwarmStageEvolve(in, err);
    ExpectNoDescendant(result);
    BOOST_CHECK_EQUAL(result.code, "UNQUALIFIED");
    BOOST_CHECK_EQUAL(err, "UNQUALIFIED");
}

BOOST_AUTO_TEST_CASE(distinct_names_are_noted_not_a_descendant)
{
    modelnet::SwarmFlag07 in = NotedEvolve();
    std::string err = "prior";
    const modelnet::SwarmFlag07Result result = modelnet::SwarmStageEvolve(in, err);
    ExpectNoDescendant(result);
    BOOST_CHECK_EQUAL(result.code, "NOTED");
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_SUITE_END()
