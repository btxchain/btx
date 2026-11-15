// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notlivefault.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_notlivefault_tests, BasicTestingSetup)

static modelnet::SwarmNotLiveFault NotedNote()
{
    modelnet::SwarmNotLiveFault note;
    note.fault_id = "fault-1";
    note.want_inject = false;
    return note;
}

BOOST_AUTO_TEST_CASE(empty_fault_id_is_fault)
{
    modelnet::SwarmNotLiveFault note = NotedNote();
    note.fault_id.clear();
    std::string err = "prior";
    const modelnet::SwarmNotLiveFaultResult result = modelnet::SwarmNoteNotLiveFault(note, err);
    BOOST_CHECK(!result.injected);
    BOOST_CHECK_EQUAL(result.code, "FAULT");
    BOOST_CHECK_EQUAL(err, "FAULT");
}

BOOST_AUTO_TEST_CASE(want_inject_is_not_injected)
{
    modelnet::SwarmNotLiveFault note = NotedNote();
    note.want_inject = true;
    std::string err = "prior";
    const modelnet::SwarmNotLiveFaultResult result = modelnet::SwarmNoteNotLiveFault(note, err);
    BOOST_CHECK(!result.injected);
    BOOST_CHECK_EQUAL(result.code, "NOT_INJECTED");
    BOOST_CHECK_EQUAL(err, "NOT_INJECTED");
}

BOOST_AUTO_TEST_CASE(plain_note_is_noted)
{
    modelnet::SwarmNotLiveFault note = NotedNote();
    std::string err = "prior";
    const modelnet::SwarmNotLiveFaultResult result = modelnet::SwarmNoteNotLiveFault(note, err);
    BOOST_CHECK(!result.injected);
    BOOST_CHECK_EQUAL(result.code, "NOTED");
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_SUITE_END()
