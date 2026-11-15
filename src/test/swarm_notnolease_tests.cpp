// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnolease.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <cstdint>
#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_notnolease_tests, BasicTestingSetup)

static modelnet::SwarmNotNoLease NotedNote()
{
    modelnet::SwarmNotNoLease note;
    note.lease_id = "lease-1";
    note.expired = false;
    note.want_spend = false;
    return note;
}

BOOST_AUTO_TEST_CASE(empty_lease_id_is_lease)
{
    modelnet::SwarmNotNoLease note = NotedNote();
    note.lease_id.clear();
    note.expired = true;
    note.want_spend = true;
    std::string err = "prior";
    const modelnet::SwarmNotNoLeaseResult result = modelnet::SwarmNoteNotNoLease(note, err);
    BOOST_CHECK(!result.spent);
    BOOST_CHECK_EQUAL(result.atoms, 0);
    BOOST_CHECK_EQUAL(result.code, "LEASE");
    BOOST_CHECK_EQUAL(err, "LEASE");
}

BOOST_AUTO_TEST_CASE(expired_is_held)
{
    modelnet::SwarmNotNoLease note = NotedNote();
    note.expired = true;
    note.want_spend = false;
    std::string err = "prior";
    const modelnet::SwarmNotNoLeaseResult result = modelnet::SwarmNoteNotNoLease(note, err);
    BOOST_CHECK(!result.spent);
    BOOST_CHECK_EQUAL(result.atoms, 0);
    BOOST_CHECK_EQUAL(result.code, "HELD");
    BOOST_CHECK_EQUAL(err, "HELD");
}

BOOST_AUTO_TEST_CASE(want_spend_while_not_expired_is_held)
{
    modelnet::SwarmNotNoLease note = NotedNote();
    note.expired = false;
    note.want_spend = true;
    std::string err = "prior";
    const modelnet::SwarmNotNoLeaseResult result = modelnet::SwarmNoteNotNoLease(note, err);
    BOOST_CHECK(!result.spent);
    BOOST_CHECK_EQUAL(result.atoms, 0);
    BOOST_CHECK_EQUAL(result.code, "HELD");
    BOOST_CHECK_EQUAL(err, "HELD");
}

BOOST_AUTO_TEST_CASE(plain_is_noted)
{
    modelnet::SwarmNotNoLease note = NotedNote();
    note.expired = false;
    note.want_spend = false;
    std::string err = "prior";
    const modelnet::SwarmNotNoLeaseResult result = modelnet::SwarmNoteNotNoLease(note, err);
    BOOST_CHECK(!result.spent);
    BOOST_CHECK_EQUAL(result.atoms, 0);
    BOOST_CHECK_EQUAL(result.code, "NOTED");
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_SUITE_END()
