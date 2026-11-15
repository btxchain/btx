// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notschedwit.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_notschedwit_tests, BasicTestingSetup)

static modelnet::SwarmNotSchedWit NotedNote()
{
    modelnet::SwarmNotSchedWit note;
    note.scheduler_id = "scheduler-1";
    note.want_sign = false;
    return note;
}

BOOST_AUTO_TEST_CASE(empty_scheduler_id_is_scheduler)
{
    modelnet::SwarmNotSchedWit note = NotedNote();
    note.scheduler_id.clear();
    note.want_sign = true;
    std::string err = "prior";
    const modelnet::SwarmNotSchedWitResult result = modelnet::SwarmNoteNotSchedWit(note, err);
    BOOST_CHECK(!result.signed_witness);
    BOOST_CHECK(!result.broadcast);
    BOOST_CHECK_EQUAL(result.code, "SCHEDULER");
    BOOST_CHECK_EQUAL(err, "SCHEDULER");
}

BOOST_AUTO_TEST_CASE(want_sign_is_no_witness)
{
    modelnet::SwarmNotSchedWit note = NotedNote();
    note.want_sign = true;
    std::string err = "prior";
    const modelnet::SwarmNotSchedWitResult result = modelnet::SwarmNoteNotSchedWit(note, err);
    BOOST_CHECK(!result.signed_witness);
    BOOST_CHECK(!result.broadcast);
    BOOST_CHECK_EQUAL(result.code, "NO_WITNESS");
    BOOST_CHECK_EQUAL(err, "NO_WITNESS");
}

BOOST_AUTO_TEST_CASE(plain_note_is_noted)
{
    modelnet::SwarmNotSchedWit note = NotedNote();
    note.want_sign = false;
    std::string err = "prior";
    const modelnet::SwarmNotSchedWitResult result = modelnet::SwarmNoteNotSchedWit(note, err);
    BOOST_CHECK(!result.signed_witness);
    BOOST_CHECK(!result.broadcast);
    BOOST_CHECK_EQUAL(result.code, "NOTED");
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_SUITE_END()
