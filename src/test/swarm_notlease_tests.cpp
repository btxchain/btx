// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notlease.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_notlease_tests, BasicTestingSetup)

static modelnet::SwarmNotLease NotedNote()
{
    modelnet::SwarmNotLease note;
    note.lease_id = "lease-1";
    note.want_replace = false;
    return note;
}

BOOST_AUTO_TEST_CASE(empty_lease_id_is_lease)
{
    modelnet::SwarmNotLease note = NotedNote();
    note.lease_id.clear();
    std::string err = "prior";
    const modelnet::SwarmNotLeaseResult result = modelnet::SwarmNoteNotLease(note, err);
    BOOST_CHECK(!result.replaced);
    BOOST_CHECK_EQUAL(result.code, "LEASE");
    BOOST_CHECK_EQUAL(err, "LEASE");
}

BOOST_AUTO_TEST_CASE(want_replace_is_not_injected)
{
    modelnet::SwarmNotLease note = NotedNote();
    note.want_replace = true;
    std::string err = "prior";
    const modelnet::SwarmNotLeaseResult result = modelnet::SwarmNoteNotLease(note, err);
    BOOST_CHECK(!result.replaced);
    BOOST_CHECK_EQUAL(result.code, "NOT_INJECTED");
    BOOST_CHECK_EQUAL(err, "NOT_INJECTED");
}

BOOST_AUTO_TEST_CASE(plain_note_is_noted)
{
    modelnet::SwarmNotLease note = NotedNote();
    std::string err = "prior";
    const modelnet::SwarmNotLeaseResult result = modelnet::SwarmNoteNotLease(note, err);
    BOOST_CHECK(!result.replaced);
    BOOST_CHECK_EQUAL(result.code, "NOTED");
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_SUITE_END()
