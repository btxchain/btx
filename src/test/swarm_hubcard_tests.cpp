// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_hubcard.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_hubcard_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(empty_card_is_card)
{
    modelnet::SwarmHubCard card;
    card.want_trust = false;
    std::string err = "prior";
    const modelnet::SwarmHubCardResult result = modelnet::SwarmNoteHubCard(card, err);
    BOOST_CHECK(!result.trusted);
    BOOST_CHECK_EQUAL(result.code, "CARD");
    BOOST_CHECK_EQUAL(err, "CARD");
}

BOOST_AUTO_TEST_CASE(want_trust_is_held)
{
    modelnet::SwarmHubCard card;
    card.card_id = "hub-1";
    card.want_trust = true;
    std::string err = "prior";
    const modelnet::SwarmHubCardResult result = modelnet::SwarmNoteHubCard(card, err);
    BOOST_CHECK(!result.trusted);
    BOOST_CHECK_EQUAL(result.code, "HELD");
    BOOST_CHECK_EQUAL(err, "HELD");
}

BOOST_AUTO_TEST_CASE(want_trust_false_is_noted)
{
    modelnet::SwarmHubCard card;
    card.card_id = "hub-1";
    card.want_trust = false;
    std::string err = "prior";
    const modelnet::SwarmHubCardResult result = modelnet::SwarmNoteHubCard(card, err);
    BOOST_CHECK(!result.trusted);
    BOOST_CHECK_EQUAL(result.code, "NOTED");
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_SUITE_END()
