// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_guesthold/codes.h>
#include <modelnet/swarm_guesthold/limits.h>
#include <modelnet/swarm_guesthold/swarm_guesthold.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_guesthold_replay_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(second_check_of_the_same_name_is_replay)
{
    modelnet::SwarmGuestHold plane;
    std::string err = "prior";

    BOOST_REQUIRE(!plane.Check("guest-1", err));
    BOOST_REQUIRE(err == modelnet::kSwarmGuestHoldNotPassed);
    BOOST_REQUIRE_EQUAL(err, "NOT_PASSED");
    BOOST_REQUIRE(plane.checked("guest-1"));
    BOOST_REQUIRE(plane.stored_name("guest-1") == "guest-1");
    BOOST_REQUIRE(plane.check_count() == 1);
    BOOST_REQUIRE(!plane.passed());
    BOOST_REQUIRE(!plane.logged_in());

    err = "prior";
    BOOST_REQUIRE(!plane.Check("guest-1", err));
    BOOST_REQUIRE(err == modelnet::kSwarmGuestHoldReplay);
    BOOST_REQUIRE_EQUAL(err, "REPLAY");
    BOOST_REQUIRE(plane.checked("guest-1"));
    BOOST_REQUIRE(plane.stored_name("guest-1") == "guest-1");
    BOOST_REQUIRE(plane.check_count() == 1);
    BOOST_REQUIRE(!plane.passed());
    BOOST_REQUIRE(plane.passed() == modelnet::kSwarmGuestHoldPassed);
    BOOST_REQUIRE(!plane.logged_in());
    BOOST_REQUIRE(plane.logged_in() == modelnet::kSwarmGuestHoldLoggedIn);
    BOOST_REQUIRE_EQUAL(plane.bytes_moved(), 0);
    BOOST_REQUIRE(!plane.gpu());
    BOOST_REQUIRE(!plane.launched());

    err = "prior";
    BOOST_REQUIRE(!plane.Check("guest-1", err));
    BOOST_REQUIRE(err == modelnet::kSwarmGuestHoldReplay);
    BOOST_REQUIRE_EQUAL(err, "REPLAY");
    BOOST_REQUIRE(plane.stored_name("guest-1") == "guest-1");
    BOOST_REQUIRE(plane.check_count() == 1);
    BOOST_REQUIRE(!plane.passed());
    BOOST_REQUIRE(!plane.logged_in());
    BOOST_REQUIRE_EQUAL(plane.bytes_moved(), 0);
}

BOOST_AUTO_TEST_CASE(empty_name_is_guest_before_replay)
{
    modelnet::SwarmGuestHold plane;
    std::string err = "prior";

    BOOST_REQUIRE(!plane.Check("guest-1", err));
    BOOST_REQUIRE(err == modelnet::kSwarmGuestHoldNotPassed);
    BOOST_REQUIRE_EQUAL(err, "NOT_PASSED");

    err = "prior";
    BOOST_REQUIRE(!plane.Check("", err));
    BOOST_REQUIRE(err == modelnet::kSwarmGuestHoldGuest);
    BOOST_REQUIRE_EQUAL(err, "GUEST");
    BOOST_REQUIRE(plane.stored_name("guest-1") == "guest-1");
    BOOST_REQUIRE(plane.check_count() == 1);
    BOOST_REQUIRE(!plane.passed());
    BOOST_REQUIRE(!plane.logged_in());
    BOOST_REQUIRE_EQUAL(plane.bytes_moved(), 0);
}

BOOST_AUTO_TEST_CASE(replay_keeps_the_first_when_another_name_is_stored)
{
    modelnet::SwarmGuestHold plane;
    std::string err = "prior";

    BOOST_REQUIRE(!plane.Check("guest-1", err));
    BOOST_REQUIRE(err == modelnet::kSwarmGuestHoldNotPassed);
    BOOST_REQUIRE_EQUAL(err, "NOT_PASSED");

    err = "prior";
    BOOST_REQUIRE(!plane.Check("guest-2", err));
    BOOST_REQUIRE(err == modelnet::kSwarmGuestHoldNotPassed);
    BOOST_REQUIRE_EQUAL(err, "NOT_PASSED");

    err = "prior";
    BOOST_REQUIRE(!plane.Check("guest-1", err));
    BOOST_REQUIRE(err == modelnet::kSwarmGuestHoldReplay);
    BOOST_REQUIRE_EQUAL(err, "REPLAY");
    BOOST_REQUIRE(plane.checked("guest-1"));
    BOOST_REQUIRE(plane.checked("guest-2"));
    BOOST_REQUIRE(plane.stored_name("guest-1") == "guest-1");
    BOOST_REQUIRE(plane.stored_name("guest-2") == "guest-2");
    BOOST_REQUIRE(plane.check_count() == 2);
    BOOST_REQUIRE(!plane.passed());
    BOOST_REQUIRE(!plane.logged_in());
    BOOST_REQUIRE_EQUAL(plane.bytes_moved(), 0);
    BOOST_REQUIRE(plane.bytes_moved() == modelnet::kSwarmGuestHoldBytesMoved);
    BOOST_REQUIRE(!plane.gpu());
    BOOST_REQUIRE(!plane.launched());
}

BOOST_AUTO_TEST_SUITE_END()
