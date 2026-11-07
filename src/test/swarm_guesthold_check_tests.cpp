// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_guesthold/codes.h>
#include <modelnet/swarm_guesthold/limits.h>
#include <modelnet/swarm_guesthold/swarm_guesthold.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_guesthold_check_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(stored_check_stays_unpassed)
{
    modelnet::SwarmGuestHold plane;
    std::string err = "prior";

    BOOST_REQUIRE(!plane.checked("guest-1"));
    BOOST_REQUIRE(plane.stored_name("guest-1").empty());
    BOOST_REQUIRE(plane.check_count() == 0);
    BOOST_REQUIRE(!plane.passed());
    BOOST_REQUIRE(!plane.logged_in());
    BOOST_REQUIRE_EQUAL(plane.bytes_moved(), 0);
    BOOST_REQUIRE(!plane.gpu());
    BOOST_REQUIRE(!plane.launched());

    BOOST_REQUIRE(!plane.Check("guest-1", err));
    BOOST_REQUIRE(err == modelnet::kSwarmGuestHoldNotPassed);
    BOOST_REQUIRE_EQUAL(err, "NOT_PASSED");
    BOOST_REQUIRE(plane.checked("guest-1"));
    BOOST_REQUIRE(plane.stored_name("guest-1") == "guest-1");
    BOOST_REQUIRE(plane.check_count() == 1);
    BOOST_REQUIRE(!plane.passed());
    BOOST_REQUIRE(plane.passed() == modelnet::kSwarmGuestHoldPassed);
    BOOST_REQUIRE(!plane.logged_in());
    BOOST_REQUIRE(plane.logged_in() == modelnet::kSwarmGuestHoldLoggedIn);
    BOOST_REQUIRE_EQUAL(plane.bytes_moved(), 0);
    BOOST_REQUIRE(plane.bytes_moved() == modelnet::kSwarmGuestHoldBytesMoved);
    BOOST_REQUIRE(!plane.gpu());
    BOOST_REQUIRE(plane.gpu() == modelnet::kSwarmGuestHoldGpu);
    BOOST_REQUIRE(!plane.launched());
    BOOST_REQUIRE(plane.launched() == modelnet::kSwarmGuestHoldLaunched);
}

BOOST_AUTO_TEST_CASE(a_second_distinct_name_is_stored_beside_the_first)
{
    modelnet::SwarmGuestHold plane;
    std::string err = "prior";

    BOOST_REQUIRE(!plane.Check("guest-1", err));
    BOOST_REQUIRE(err == modelnet::kSwarmGuestHoldNotPassed);
    BOOST_REQUIRE_EQUAL(err, "NOT_PASSED");
    BOOST_REQUIRE(plane.checked("guest-1"));
    BOOST_REQUIRE(plane.stored_name("guest-1") == "guest-1");
    BOOST_REQUIRE(!plane.passed());
    BOOST_REQUIRE(!plane.logged_in());

    err = "prior";
    BOOST_REQUIRE(!plane.Check("guest-2", err));
    BOOST_REQUIRE(err == modelnet::kSwarmGuestHoldNotPassed);
    BOOST_REQUIRE_EQUAL(err, "NOT_PASSED");
    BOOST_REQUIRE(plane.checked("guest-1"));
    BOOST_REQUIRE(plane.checked("guest-2"));
    BOOST_REQUIRE(plane.stored_name("guest-1") == "guest-1");
    BOOST_REQUIRE(plane.stored_name("guest-2") == "guest-2");
    BOOST_REQUIRE(plane.check_count() == 2);
    BOOST_REQUIRE(!plane.passed());
    BOOST_REQUIRE(!plane.logged_in());
    BOOST_REQUIRE_EQUAL(plane.bytes_moved(), 0);
    BOOST_REQUIRE(!plane.gpu());
    BOOST_REQUIRE(!plane.launched());
}

BOOST_AUTO_TEST_CASE(space_and_code_word_are_stored_and_stay_unpassed)
{
    modelnet::SwarmGuestHold plane;
    std::string err = "prior";

    BOOST_REQUIRE(!plane.Check(" ", err));
    BOOST_REQUIRE(err == modelnet::kSwarmGuestHoldNotPassed);
    BOOST_REQUIRE_EQUAL(err, "NOT_PASSED");
    BOOST_REQUIRE(plane.checked(" "));
    BOOST_REQUIRE(plane.stored_name(" ") == " ");
    BOOST_REQUIRE(!plane.passed());
    BOOST_REQUIRE(!plane.logged_in());

    err = "prior";
    BOOST_REQUIRE(!plane.Check("GUEST", err));
    BOOST_REQUIRE(err == modelnet::kSwarmGuestHoldNotPassed);
    BOOST_REQUIRE_EQUAL(err, "NOT_PASSED");
    BOOST_REQUIRE(plane.checked("GUEST"));
    BOOST_REQUIRE(plane.stored_name("GUEST") == "GUEST");
    BOOST_REQUIRE(plane.checked(" "));
    BOOST_REQUIRE(plane.check_count() == 2);
    BOOST_REQUIRE(!plane.passed());
    BOOST_REQUIRE(!plane.logged_in());
    BOOST_REQUIRE_EQUAL(plane.bytes_moved(), 0);
    BOOST_REQUIRE(!plane.gpu());
    BOOST_REQUIRE(!plane.launched());
}

BOOST_AUTO_TEST_SUITE_END()
