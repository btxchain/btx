// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notspendkey.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_notspendkey_tests, BasicTestingSetup)

static modelnet::SwarmNotSpendKey NotedNote()
{
    modelnet::SwarmNotSpendKey note;
    note.scheduler_id = "scheduler-1";
    note.want_spend = false;
    return note;
}

BOOST_AUTO_TEST_CASE(empty_scheduler_id_is_scheduler)
{
    modelnet::SwarmNotSpendKey note = NotedNote();
    note.scheduler_id.clear();
    note.want_spend = true;
    std::string err = "prior";
    const modelnet::SwarmNotSpendKeyResult result = modelnet::SwarmNoteNotSpendKey(note, err);
    BOOST_CHECK(!result.signed_spend);
    BOOST_CHECK(!result.broadcast);
    BOOST_CHECK_EQUAL(result.code, "SCHEDULER");
    BOOST_CHECK_EQUAL(err, "SCHEDULER");
}

BOOST_AUTO_TEST_CASE(want_spend_is_no_key)
{
    modelnet::SwarmNotSpendKey note = NotedNote();
    note.want_spend = true;
    std::string err = "prior";
    const modelnet::SwarmNotSpendKeyResult result = modelnet::SwarmNoteNotSpendKey(note, err);
    BOOST_CHECK(!result.signed_spend);
    BOOST_CHECK(!result.broadcast);
    BOOST_CHECK_EQUAL(result.code, "NO_KEY");
    BOOST_CHECK_EQUAL(err, "NO_KEY");
}

BOOST_AUTO_TEST_CASE(plain_note_is_noted)
{
    modelnet::SwarmNotSpendKey note = NotedNote();
    note.want_spend = false;
    std::string err = "prior";
    const modelnet::SwarmNotSpendKeyResult result = modelnet::SwarmNoteNotSpendKey(note, err);
    BOOST_CHECK(!result.signed_spend);
    BOOST_CHECK(!result.broadcast);
    BOOST_CHECK_EQUAL(result.code, "NOTED");
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_SUITE_END()
