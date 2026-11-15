// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notpaycrash.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_notpaycrash_tests, BasicTestingSetup)

static modelnet::SwarmNotPayCrash NotedNote()
{
    modelnet::SwarmNotPayCrash note;
    note.earn_id = "earn-1";
    note.want_settle = false;
    return note;
}

BOOST_AUTO_TEST_CASE(empty_earn_id_is_earn)
{
    modelnet::SwarmNotPayCrash note = NotedNote();
    note.earn_id.clear();
    std::string err = "prior";
    const modelnet::SwarmNotPayCrashResult result = modelnet::SwarmNoteNotPayCrash(note, err);
    BOOST_CHECK(!result.settled);
    BOOST_CHECK(!result.broadcast);
    BOOST_CHECK_EQUAL(result.code, "EARN");
    BOOST_CHECK_EQUAL(err, "EARN");
}

BOOST_AUTO_TEST_CASE(want_settle_is_not_settled)
{
    modelnet::SwarmNotPayCrash note = NotedNote();
    note.want_settle = true;
    std::string err = "prior";
    const modelnet::SwarmNotPayCrashResult result = modelnet::SwarmNoteNotPayCrash(note, err);
    BOOST_CHECK(!result.settled);
    BOOST_CHECK(!result.broadcast);
    BOOST_CHECK_EQUAL(result.code, "NOT_SETTLED");
    BOOST_CHECK_EQUAL(err, "NOT_SETTLED");
}

BOOST_AUTO_TEST_CASE(plain_note_is_noted)
{
    modelnet::SwarmNotPayCrash note = NotedNote();
    note.want_settle = false;
    std::string err = "prior";
    const modelnet::SwarmNotPayCrashResult result = modelnet::SwarmNoteNotPayCrash(note, err);
    BOOST_CHECK(!result.settled);
    BOOST_CHECK(!result.broadcast);
    BOOST_CHECK_EQUAL(result.code, "NOTED");
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_SUITE_END()
