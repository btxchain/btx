// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_researchkey.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_researchkey_tests, BasicTestingSetup)

static modelnet::SwarmResearchKey NotedKey()
{
    modelnet::SwarmResearchKey key;
    key.key_id = "rk-1";
    key.research_key = false;
    key.want_spend = false;
    return key;
}

BOOST_AUTO_TEST_CASE(empty_key_id_is_key)
{
    modelnet::SwarmResearchKey key = NotedKey();
    key.key_id = "";
    std::string err = "prior";
    const modelnet::SwarmResearchKeyResult result = modelnet::SwarmNoteResearchKey(key, err);
    BOOST_CHECK(!result.spend_armed);
    BOOST_CHECK_EQUAL(result.code, "KEY");
    BOOST_CHECK_EQUAL(err, "KEY");
}

BOOST_AUTO_TEST_CASE(empty_key_id_wins_over_research_and_spend)
{
    modelnet::SwarmResearchKey key = NotedKey();
    key.key_id = "";
    key.research_key = true;
    key.want_spend = true;
    std::string err = "prior";
    const modelnet::SwarmResearchKeyResult result = modelnet::SwarmNoteResearchKey(key, err);
    BOOST_CHECK(!result.spend_armed);
    BOOST_CHECK_EQUAL(result.code, "KEY");
    BOOST_CHECK_EQUAL(err, "KEY");
}

BOOST_AUTO_TEST_CASE(research_key_wanting_spend_is_research)
{
    modelnet::SwarmResearchKey key = NotedKey();
    key.research_key = true;
    key.want_spend = true;
    std::string err = "prior";
    const modelnet::SwarmResearchKeyResult result = modelnet::SwarmNoteResearchKey(key, err);
    BOOST_CHECK(!result.spend_armed);
    BOOST_CHECK_EQUAL(result.code, "RESEARCH");
    BOOST_CHECK_EQUAL(err, "RESEARCH");
}

BOOST_AUTO_TEST_CASE(want_spend_is_spend_refused)
{
    modelnet::SwarmResearchKey key = NotedKey();
    key.want_spend = true;
    std::string err = "prior";
    const modelnet::SwarmResearchKeyResult result = modelnet::SwarmNoteResearchKey(key, err);
    BOOST_CHECK(!result.spend_armed);
    BOOST_CHECK_EQUAL(result.code, "SPEND_REFUSED");
    BOOST_CHECK_EQUAL(err, "SPEND_REFUSED");
}

BOOST_AUTO_TEST_CASE(research_key_without_spend_is_noted)
{
    modelnet::SwarmResearchKey key = NotedKey();
    key.research_key = true;
    key.want_spend = false;
    std::string err = "prior";
    const modelnet::SwarmResearchKeyResult result = modelnet::SwarmNoteResearchKey(key, err);
    BOOST_CHECK(!result.spend_armed);
    BOOST_CHECK_EQUAL(result.code, "NOTED");
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_CASE(plain_note_is_noted)
{
    modelnet::SwarmResearchKey key = NotedKey();
    std::string err = "prior";
    const modelnet::SwarmResearchKeyResult result = modelnet::SwarmNoteResearchKey(key, err);
    BOOST_CHECK(!result.spend_armed);
    BOOST_CHECK_EQUAL(result.code, "NOTED");
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_SUITE_END()
