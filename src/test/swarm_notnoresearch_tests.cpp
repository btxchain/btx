// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnoresearch.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <cstdint>
#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_notnoresearch_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(empty_key_id_is_key)
{
    modelnet::SwarmNotNoResearch note;
    note.key_id.clear();
    note.research_key = true;
    note.want_spend = true;
    std::string err = "prior";
    const modelnet::SwarmNotNoResearchResult result = modelnet::SwarmNoteNotNoResearch(note, err);
    BOOST_CHECK(!result.spent);
    BOOST_CHECK_EQUAL(result.atoms, 0);
    BOOST_CHECK_EQUAL(result.code, "KEY");
    BOOST_CHECK_EQUAL(err, "KEY");
}

BOOST_AUTO_TEST_CASE(research_key_is_no_spend)
{
    modelnet::SwarmNotNoResearch note;
    note.key_id = "key-1";
    note.research_key = true;
    note.want_spend = false;
    std::string err = "prior";
    const modelnet::SwarmNotNoResearchResult result = modelnet::SwarmNoteNotNoResearch(note, err);
    BOOST_CHECK(!result.spent);
    BOOST_CHECK_EQUAL(result.atoms, 0);
    BOOST_CHECK_EQUAL(result.code, "NO_SPEND");
    BOOST_CHECK_EQUAL(err, "NO_SPEND");
}

BOOST_AUTO_TEST_CASE(want_spend_is_no_spend)
{
    modelnet::SwarmNotNoResearch note;
    note.key_id = "key-1";
    note.research_key = false;
    note.want_spend = true;
    std::string err = "prior";
    const modelnet::SwarmNotNoResearchResult result = modelnet::SwarmNoteNotNoResearch(note, err);
    BOOST_CHECK(!result.spent);
    BOOST_CHECK_EQUAL(result.atoms, 0);
    BOOST_CHECK_EQUAL(result.code, "NO_SPEND");
    BOOST_CHECK_EQUAL(err, "NO_SPEND");
}

BOOST_AUTO_TEST_CASE(plain_note_is_noted)
{
    modelnet::SwarmNotNoResearch note;
    note.key_id = "key-1";
    note.research_key = false;
    note.want_spend = false;
    std::string err = "prior";
    const modelnet::SwarmNotNoResearchResult result = modelnet::SwarmNoteNotNoResearch(note, err);
    BOOST_CHECK(!result.spent);
    BOOST_CHECK_EQUAL(result.atoms, 0);
    BOOST_CHECK_EQUAL(result.code, "NOTED");
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_SUITE_END()
