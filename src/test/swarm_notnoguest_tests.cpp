// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnoguest.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_notnoguest_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(empty_host_id_is_host)
{
    modelnet::SwarmNotNoGuest note;
    note.want_agent = true;
    std::string err = "prior";
    const modelnet::SwarmNotNoGuestResult result = modelnet::SwarmNoteNotNoGuest(note, err);
    BOOST_CHECK(!result.guest_agent);
    BOOST_CHECK(!result.passed);
    BOOST_CHECK_EQUAL(result.code, "HOST");
    BOOST_CHECK_EQUAL(err, "HOST");
}

BOOST_AUTO_TEST_CASE(want_agent_is_unqualified)
{
    modelnet::SwarmNotNoGuest note;
    note.host_id = "host-a";
    note.want_agent = true;
    std::string err = "prior";
    const modelnet::SwarmNotNoGuestResult result = modelnet::SwarmNoteNotNoGuest(note, err);
    BOOST_CHECK(!result.guest_agent);
    BOOST_CHECK(!result.passed);
    BOOST_CHECK_EQUAL(result.code, "UNQUALIFIED");
    BOOST_CHECK_EQUAL(err, "UNQUALIFIED");
}

BOOST_AUTO_TEST_CASE(plain_note_is_noted)
{
    modelnet::SwarmNotNoGuest note;
    note.host_id = "host-a";
    note.want_agent = false;
    std::string err = "prior";
    const modelnet::SwarmNotNoGuestResult result = modelnet::SwarmNoteNotNoGuest(note, err);
    BOOST_CHECK(!result.guest_agent);
    BOOST_CHECK(!result.passed);
    BOOST_CHECK_EQUAL(result.code, "NOTED");
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_SUITE_END()
