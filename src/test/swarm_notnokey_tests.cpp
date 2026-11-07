// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnokey.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_notnokey_tests, BasicTestingSetup)

static modelnet::SwarmNotNoKey NotedNote()
{
    modelnet::SwarmNotNoKey note;
    note.role_id = "other";
    note.research_or_scheduler = false;
    note.want_spend = false;
    return note;
}

BOOST_AUTO_TEST_CASE(empty_role_id_is_role)
{
    modelnet::SwarmNotNoKey note = NotedNote();
    note.role_id.clear();
    note.research_or_scheduler = true;
    note.want_spend = true;
    std::string err = "prior";
    const modelnet::SwarmNotNoKeyResult result = modelnet::SwarmNoteNotNoKey(note, err);
    BOOST_CHECK(!result.granted);
    BOOST_CHECK(!result.spent);
    BOOST_CHECK_EQUAL(result.code, "ROLE");
    BOOST_CHECK_EQUAL(err, "ROLE");
}

BOOST_AUTO_TEST_CASE(research_or_scheduler_is_no_key)
{
    modelnet::SwarmNotNoKey note = NotedNote();
    note.research_or_scheduler = true;
    note.want_spend = false;
    std::string err = "prior";
    const modelnet::SwarmNotNoKeyResult result = modelnet::SwarmNoteNotNoKey(note, err);
    BOOST_CHECK(!result.granted);
    BOOST_CHECK(!result.spent);
    BOOST_CHECK_EQUAL(result.code, "NO_KEY");
    BOOST_CHECK_EQUAL(err, "NO_KEY");
}

BOOST_AUTO_TEST_CASE(want_spend_on_another_role_is_no_key)
{
    modelnet::SwarmNotNoKey note = NotedNote();
    note.research_or_scheduler = false;
    note.want_spend = true;
    std::string err = "prior";
    const modelnet::SwarmNotNoKeyResult result = modelnet::SwarmNoteNotNoKey(note, err);
    BOOST_CHECK(!result.granted);
    BOOST_CHECK(!result.spent);
    BOOST_CHECK_EQUAL(result.code, "NO_KEY");
    BOOST_CHECK_EQUAL(err, "NO_KEY");
}

BOOST_AUTO_TEST_CASE(plain_other_role_is_noted)
{
    modelnet::SwarmNotNoKey note = NotedNote();
    note.research_or_scheduler = false;
    note.want_spend = false;
    std::string err = "prior";
    const modelnet::SwarmNotNoKeyResult result = modelnet::SwarmNoteNotNoKey(note, err);
    BOOST_CHECK(!result.granted);
    BOOST_CHECK(!result.spent);
    BOOST_CHECK_EQUAL(result.code, "NOTED");
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_SUITE_END()
