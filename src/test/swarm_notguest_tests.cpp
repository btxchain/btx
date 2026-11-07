// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notguest.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_notguest_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(empty_guest_id_is_guest)
{
    modelnet::SwarmNotGuest note;
    std::string err = "prior";
    const modelnet::SwarmNotGuestResult result = modelnet::SwarmNoteNotGuest(note, err);
    BOOST_CHECK_EQUAL(result.passed, false);
    BOOST_CHECK_EQUAL(result.code, "GUEST");
    BOOST_CHECK_EQUAL(err, "GUEST");
}

BOOST_AUTO_TEST_CASE(want_pass_is_unqualified)
{
    modelnet::SwarmNotGuest note;
    note.guest_id = "guest-1";
    note.want_pass = true;
    std::string err = "prior";
    const modelnet::SwarmNotGuestResult result = modelnet::SwarmNoteNotGuest(note, err);
    BOOST_CHECK_EQUAL(result.passed, false);
    BOOST_CHECK_EQUAL(result.code, "UNQUALIFIED");
    BOOST_CHECK_EQUAL(err, "UNQUALIFIED");
}

BOOST_AUTO_TEST_CASE(plain_note_is_noted)
{
    modelnet::SwarmNotGuest note;
    note.guest_id = "guest-1";
    note.want_pass = false;
    std::string err = "prior";
    const modelnet::SwarmNotGuestResult result = modelnet::SwarmNoteNotGuest(note, err);
    BOOST_CHECK_EQUAL(result.passed, false);
    BOOST_CHECK_EQUAL(result.code, "NOTED");
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_SUITE_END()
