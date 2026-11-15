// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnolive2.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_notnolive2_tests, BasicTestingSetup)

static modelnet::SwarmNotNoLive2 NotedNote()
{
    modelnet::SwarmNotNoLive2 note;
    note.fault_id = "fault-1";
    note.want_inject = false;
    return note;
}

BOOST_AUTO_TEST_CASE(empty_fault_id_is_fault)
{
    modelnet::SwarmNotNoLive2 note = NotedNote();
    note.fault_id.clear();
    note.want_inject = true;
    std::string err = "prior";
    const modelnet::SwarmNotNoLive2Result result = modelnet::SwarmNoteNotNoLive2(note, err);
    BOOST_CHECK(!result.injected);
    BOOST_CHECK(!result.bytes_moved);
    BOOST_CHECK_EQUAL(result.code, "FAULT");
    BOOST_CHECK_EQUAL(err, "FAULT");
}

BOOST_AUTO_TEST_CASE(want_inject_is_not_injected)
{
    modelnet::SwarmNotNoLive2 note = NotedNote();
    note.want_inject = true;
    std::string err = "prior";
    const modelnet::SwarmNotNoLive2Result result = modelnet::SwarmNoteNotNoLive2(note, err);
    BOOST_CHECK(!result.injected);
    BOOST_CHECK(!result.bytes_moved);
    BOOST_CHECK_EQUAL(result.code, "NOT_INJECTED");
    BOOST_CHECK_EQUAL(err, "NOT_INJECTED");
}

BOOST_AUTO_TEST_CASE(plain_note_is_noted)
{
    modelnet::SwarmNotNoLive2 note = NotedNote();
    std::string err = "prior";
    const modelnet::SwarmNotNoLive2Result result = modelnet::SwarmNoteNotNoLive2(note, err);
    BOOST_CHECK(!result.injected);
    BOOST_CHECK(!result.bytes_moved);
    BOOST_CHECK_EQUAL(result.code, "NOTED");
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_SUITE_END()
