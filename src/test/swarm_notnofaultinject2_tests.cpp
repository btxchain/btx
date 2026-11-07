// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnofaultinject2.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_notnofaultinject2_tests, BasicTestingSetup)

static modelnet::SwarmNotNoFaultInject2 NotedNote()
{
    modelnet::SwarmNotNoFaultInject2 note;
    note.fault_id = "fault-1";
    note.want_inject = false;
    return note;
}

BOOST_AUTO_TEST_CASE(empty_fault_id_is_fault)
{
    modelnet::SwarmNotNoFaultInject2 note = NotedNote();
    note.fault_id.clear();
    note.want_inject = true;
    std::string err = "prior";
    const modelnet::SwarmNotNoFaultInject2Result result = modelnet::SwarmNoteNotNoFaultInject2(note, err);
    BOOST_CHECK(!result.injected);
    BOOST_CHECK(!result.bytes_moved);
    BOOST_CHECK_EQUAL(result.code, "FAULT");
    BOOST_CHECK_EQUAL(err, "FAULT");
}

BOOST_AUTO_TEST_CASE(want_inject_is_held)
{
    modelnet::SwarmNotNoFaultInject2 note = NotedNote();
    note.want_inject = true;
    std::string err = "prior";
    const modelnet::SwarmNotNoFaultInject2Result result = modelnet::SwarmNoteNotNoFaultInject2(note, err);
    BOOST_CHECK(!result.injected);
    BOOST_CHECK(!result.bytes_moved);
    BOOST_CHECK_EQUAL(result.code, "HELD");
    BOOST_CHECK_EQUAL(err, "HELD");
}

BOOST_AUTO_TEST_CASE(plain_note_is_noted)
{
    modelnet::SwarmNotNoFaultInject2 note = NotedNote();
    std::string err = "prior";
    const modelnet::SwarmNotNoFaultInject2Result result = modelnet::SwarmNoteNotNoFaultInject2(note, err);
    BOOST_CHECK(!result.injected);
    BOOST_CHECK(!result.bytes_moved);
    BOOST_CHECK_EQUAL(result.code, "NOTED");
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_SUITE_END()
