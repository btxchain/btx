// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_votemaj.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_votemaj_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(empty_vote)
{
    modelnet::SwarmVoteMaj vote;
    vote.vote_id.clear();
    vote.majority = false;
    vote.want_graduate = false;
    vote.want_hide = false;
    std::string err;
    const modelnet::SwarmVoteMajResult result = modelnet::SwarmNoteMajority(vote, err);
    BOOST_CHECK_EQUAL(result.code, "VOTE");
    BOOST_CHECK_EQUAL(err, "VOTE");
    BOOST_CHECK(!result.graduated);
    BOOST_CHECK(!result.hidden);
}

BOOST_AUTO_TEST_CASE(majority_not_graduated)
{
    modelnet::SwarmVoteMaj vote;
    vote.vote_id = "vote-1";
    vote.majority = true;
    vote.want_graduate = false;
    vote.want_hide = false;
    std::string err;
    const modelnet::SwarmVoteMajResult result = modelnet::SwarmNoteMajority(vote, err);
    BOOST_CHECK_EQUAL(result.code, "NOT_GRADUATED");
    BOOST_CHECK_EQUAL(err, "NOT_GRADUATED");
    BOOST_CHECK(!result.graduated);
    BOOST_CHECK(!result.hidden);
}

BOOST_AUTO_TEST_CASE(want_hide_held)
{
    modelnet::SwarmVoteMaj vote;
    vote.vote_id = "vote-2";
    vote.majority = false;
    vote.want_graduate = false;
    vote.want_hide = true;
    std::string err;
    const modelnet::SwarmVoteMajResult result = modelnet::SwarmNoteMajority(vote, err);
    BOOST_CHECK_EQUAL(result.code, "HELD");
    BOOST_CHECK_EQUAL(err, "HELD");
    BOOST_CHECK(!result.graduated);
    BOOST_CHECK(!result.hidden);
}

BOOST_AUTO_TEST_CASE(noted)
{
    modelnet::SwarmVoteMaj vote;
    vote.vote_id = "vote-3";
    vote.majority = false;
    vote.want_graduate = false;
    vote.want_hide = false;
    std::string err = "stale";
    const modelnet::SwarmVoteMajResult result = modelnet::SwarmNoteMajority(vote, err);
    BOOST_CHECK_EQUAL(result.code, "NOTED");
    BOOST_CHECK(err.empty());
    BOOST_CHECK(!result.graduated);
    BOOST_CHECK(!result.hidden);
}

BOOST_AUTO_TEST_SUITE_END()
