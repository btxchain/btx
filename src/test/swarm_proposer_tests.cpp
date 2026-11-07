// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_proposer.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

BOOST_FIXTURE_TEST_SUITE(swarm_proposer_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(empty_idea_is_idea)
{
    modelnet::SwarmProposer idea;
    idea.idea_id = "";
    idea.want_propose = false;
    std::string err;
    const modelnet::SwarmProposerResult result = modelnet::SwarmNoteProposer(idea, err);
    BOOST_CHECK(!result.proposed);
    BOOST_CHECK_EQUAL(result.code, "IDEA");
    BOOST_CHECK_EQUAL(err, "IDEA");
}

BOOST_AUTO_TEST_CASE(want_propose_is_held)
{
    modelnet::SwarmProposer idea;
    idea.idea_id = "idea";
    idea.want_propose = true;
    std::string err;
    const modelnet::SwarmProposerResult result = modelnet::SwarmNoteProposer(idea, err);
    BOOST_CHECK(!result.proposed);
    BOOST_CHECK_EQUAL(result.code, "HELD");
    BOOST_CHECK_EQUAL(err, "HELD");
}

BOOST_AUTO_TEST_CASE(noted_clears_err)
{
    modelnet::SwarmProposer idea;
    idea.idea_id = "idea";
    idea.want_propose = false;
    std::string err = "stale";
    const modelnet::SwarmProposerResult result = modelnet::SwarmNoteProposer(idea, err);
    BOOST_CHECK(!result.proposed);
    BOOST_CHECK_EQUAL(result.code, "NOTED");
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_SUITE_END()
