// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_quorumdom.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_quorumdom_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(empty_vote)
{
    modelnet::SwarmQuorumDom vote;
    vote.vote_id.clear();
    vote.evaluators = 2;
    vote.domains = 2;
    vote.same_domain = false;
    vote.want_count = false;
    std::string err;
    const modelnet::SwarmQuorumDomResult result = modelnet::SwarmNoteQuorumDomain(vote, err);
    BOOST_CHECK(!result.counted);
    BOOST_CHECK_EQUAL(result.code, "VOTE");
    BOOST_CHECK_EQUAL(err, "VOTE");
}

BOOST_AUTO_TEST_CASE(evaluators_below_range)
{
    modelnet::SwarmQuorumDom vote;
    vote.vote_id = "vote-a";
    vote.evaluators = 1;
    vote.domains = 2;
    vote.same_domain = false;
    vote.want_count = false;
    std::string err;
    const modelnet::SwarmQuorumDomResult result = modelnet::SwarmNoteQuorumDomain(vote, err);
    BOOST_CHECK(!result.counted);
    BOOST_CHECK_EQUAL(result.code, "RANGE");
    BOOST_CHECK_EQUAL(err, "RANGE");
}

BOOST_AUTO_TEST_CASE(same_domain_not_quorum)
{
    modelnet::SwarmQuorumDom vote;
    vote.vote_id = "vote-b";
    vote.evaluators = 2;
    vote.domains = 2;
    vote.same_domain = true;
    vote.want_count = false;
    std::string err;
    const modelnet::SwarmQuorumDomResult result = modelnet::SwarmNoteQuorumDomain(vote, err);
    BOOST_CHECK(!result.counted);
    BOOST_CHECK_EQUAL(result.code, "NOT_QUORUM");
    BOOST_CHECK_EQUAL(err, "NOT_QUORUM");
}

BOOST_AUTO_TEST_CASE(want_count_held)
{
    modelnet::SwarmQuorumDom vote;
    vote.vote_id = "vote-c";
    vote.evaluators = 2;
    vote.domains = 2;
    vote.same_domain = false;
    vote.want_count = true;
    std::string err;
    const modelnet::SwarmQuorumDomResult result = modelnet::SwarmNoteQuorumDomain(vote, err);
    BOOST_CHECK(!result.counted);
    BOOST_CHECK_EQUAL(result.code, "HELD");
    BOOST_CHECK_EQUAL(err, "HELD");
}

BOOST_AUTO_TEST_CASE(noted)
{
    modelnet::SwarmQuorumDom vote;
    vote.vote_id = "vote-d";
    vote.evaluators = 2;
    vote.domains = 2;
    vote.same_domain = false;
    vote.want_count = false;
    std::string err = "stale";
    const modelnet::SwarmQuorumDomResult result = modelnet::SwarmNoteQuorumDomain(vote, err);
    BOOST_CHECK(!result.counted);
    BOOST_CHECK_EQUAL(result.code, "NOTED");
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_SUITE_END()
