// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_majority.h>
#include <test/util/setup_common.h>

#include <cstdint>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_majority_tests, BasicTestingSetup)

static modelnet::SwarmMajorityVote NotedVote()
{
    modelnet::SwarmMajorityVote vote;
    vote.candidate_id = "cand-1";
    vote.yes_ppm = 510000;
    vote.want_graduate = false;
    return vote;
}

BOOST_AUTO_TEST_CASE(empty_candidate_id_is_vote)
{
    modelnet::SwarmMajorityVote vote = NotedVote();
    vote.candidate_id.clear();
    vote.want_graduate = true;
    std::string err = "prior";
    const modelnet::SwarmMajorityResult result = modelnet::SwarmNoteMajority(vote, err);
    BOOST_CHECK(!result.graduated);
    BOOST_CHECK_EQUAL(result.code, "VOTE");
    BOOST_CHECK_EQUAL(err, "VOTE");
}

BOOST_AUTO_TEST_CASE(negative_yes_ppm_is_vote)
{
    modelnet::SwarmMajorityVote vote = NotedVote();
    vote.yes_ppm = -1;
    vote.want_graduate = true;
    std::string err = "prior";
    const modelnet::SwarmMajorityResult result = modelnet::SwarmNoteMajority(vote, err);
    BOOST_CHECK(!result.graduated);
    BOOST_CHECK_EQUAL(result.code, "VOTE");
    BOOST_CHECK_EQUAL(err, "VOTE");
}

BOOST_AUTO_TEST_CASE(yes_ppm_above_one_million_is_vote)
{
    modelnet::SwarmMajorityVote vote = NotedVote();
    vote.yes_ppm = 1000001;
    vote.want_graduate = true;
    std::string err = "prior";
    const modelnet::SwarmMajorityResult result = modelnet::SwarmNoteMajority(vote, err);
    BOOST_CHECK(!result.graduated);
    BOOST_CHECK_EQUAL(result.code, "VOTE");
    BOOST_CHECK_EQUAL(err, "VOTE");
}

BOOST_AUTO_TEST_CASE(want_graduate_at_majority_is_graduate_refused)
{
    modelnet::SwarmMajorityVote vote = NotedVote();
    vote.yes_ppm = 510000;
    vote.want_graduate = true;
    std::string err = "prior";
    const modelnet::SwarmMajorityResult result = modelnet::SwarmNoteMajority(vote, err);
    BOOST_CHECK(!result.graduated);
    BOOST_CHECK_EQUAL(result.code, "GRADUATE_REFUSED");
    BOOST_CHECK_EQUAL(err, "GRADUATE_REFUSED");
}

BOOST_AUTO_TEST_CASE(want_graduate_at_unanimous_ppm_is_graduate_refused)
{
    modelnet::SwarmMajorityVote vote = NotedVote();
    vote.yes_ppm = 1000000;
    vote.want_graduate = true;
    std::string err = "prior";
    const modelnet::SwarmMajorityResult result = modelnet::SwarmNoteMajority(vote, err);
    BOOST_CHECK(!result.graduated);
    BOOST_CHECK_EQUAL(result.code, "GRADUATE_REFUSED");
    BOOST_CHECK_EQUAL(err, "GRADUATE_REFUSED");
}

BOOST_AUTO_TEST_CASE(majority_without_graduate_is_noted)
{
    modelnet::SwarmMajorityVote vote = NotedVote();
    vote.yes_ppm = 510000;
    vote.want_graduate = false;
    std::string err = "prior";
    const modelnet::SwarmMajorityResult result = modelnet::SwarmNoteMajority(vote, err);
    BOOST_CHECK(!result.graduated);
    BOOST_CHECK_EQUAL(result.code, "NOTED");
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_CASE(unanimous_ppm_without_graduate_is_noted)
{
    modelnet::SwarmMajorityVote vote = NotedVote();
    vote.yes_ppm = 1000000;
    std::string err = "prior";
    const modelnet::SwarmMajorityResult result = modelnet::SwarmNoteMajority(vote, err);
    BOOST_CHECK(!result.graduated);
    BOOST_CHECK_EQUAL(result.code, "NOTED");
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_CASE(zero_yes_ppm_is_noted)
{
    modelnet::SwarmMajorityVote vote = NotedVote();
    vote.yes_ppm = 0;
    std::string err = "prior";
    const modelnet::SwarmMajorityResult result = modelnet::SwarmNoteMajority(vote, err);
    BOOST_CHECK(!result.graduated);
    BOOST_CHECK_EQUAL(result.code, "NOTED");
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_SUITE_END()
