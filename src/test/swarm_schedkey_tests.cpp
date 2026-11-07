// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_schedkey.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_schedkey_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(empty_scheduler_id_is_key)
{
    std::string err = "prior";
    modelnet::SwarmSchedKey note;
    note.want_spend_key = true;
    const modelnet::SwarmSchedKeyResult result = modelnet::SwarmNoteSchedKey(note, err);
    BOOST_CHECK(!result.spend_armed);
    BOOST_CHECK_EQUAL(result.code, "KEY");
    BOOST_CHECK_EQUAL(err, "KEY");
}

BOOST_AUTO_TEST_CASE(want_spend_key_is_no_key)
{
    std::string err = "prior";
    modelnet::SwarmSchedKey note;
    note.scheduler_id = "sched-a";
    note.want_spend_key = true;
    const modelnet::SwarmSchedKeyResult result = modelnet::SwarmNoteSchedKey(note, err);
    BOOST_CHECK(!result.spend_armed);
    BOOST_CHECK_EQUAL(result.code, "NO_KEY");
    BOOST_CHECK_EQUAL(err, "NO_KEY");
}

BOOST_AUTO_TEST_CASE(plain_note_is_noted)
{
    std::string err = "prior";
    modelnet::SwarmSchedKey note;
    note.scheduler_id = "sched-a";
    note.want_spend_key = false;
    const modelnet::SwarmSchedKeyResult result = modelnet::SwarmNoteSchedKey(note, err);
    BOOST_CHECK(!result.spend_armed);
    BOOST_CHECK_EQUAL(result.code, "NOTED");
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_SUITE_END()
