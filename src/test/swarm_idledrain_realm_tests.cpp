// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_idledrain/idledrain.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_idledrain_realm_tests, BasicTestingSetup)

static void ExpectQuiet(const modelnet::SwarmIdleDrain& plane)
{
    BOOST_REQUIRE_EQUAL(plane.bytes_moved(), 0);
    BOOST_REQUIRE(!plane.gpu());
    BOOST_REQUIRE(!plane.launched());
}

BOOST_AUTO_TEST_CASE(bytes_stay_zero_gpu_and_launch_stay_false)
{
    modelnet::SwarmIdleDrain plane;
    ExpectQuiet(plane);

    std::string err = "prior";
    BOOST_REQUIRE(plane.Open(err));
    BOOST_REQUIRE(err.empty());
    ExpectQuiet(plane);

    BOOST_REQUIRE(plane.Admit(err));
    BOOST_REQUIRE(err.empty());
    ExpectQuiet(plane);

    err = "prior";
    BOOST_REQUIRE(!plane.Open(err));
    BOOST_REQUIRE_EQUAL(err, "REPLAY");
    ExpectQuiet(plane);

    err = "prior";
    BOOST_REQUIRE(!plane.Drain("nope", err));
    BOOST_REQUIRE_EQUAL(err, "REASON");
    BOOST_REQUIRE_EQUAL(plane.workers(), 2);
    ExpectQuiet(plane);

    BOOST_REQUIRE(plane.Drain("battery", err));
    BOOST_REQUIRE(err.empty());
    BOOST_REQUIRE_EQUAL(plane.workers(), 0);
    ExpectQuiet(plane);

    err = "prior";
    BOOST_REQUIRE(!plane.Drain("thermal", err));
    BOOST_REQUIRE_EQUAL(err, "REPLAY");
    ExpectQuiet(plane);

    err = "prior";
    BOOST_REQUIRE(!plane.Admit(err));
    BOOST_REQUIRE_EQUAL(err, "DRAINED");
    BOOST_REQUIRE_EQUAL(plane.workers(), 0);
    ExpectQuiet(plane);
}

BOOST_AUTO_TEST_CASE(quiet_holds_at_the_cap)
{
    modelnet::SwarmIdleDrain plane;
    std::string err = "prior";

    BOOST_REQUIRE(plane.Open(err));
    for (int i = 0; i < 63; ++i) {
        BOOST_REQUIRE(plane.Admit(err));
    }
    BOOST_REQUIRE_EQUAL(plane.workers(), 64);
    ExpectQuiet(plane);

    BOOST_REQUIRE(!plane.Admit(err));
    BOOST_REQUIRE_EQUAL(err, "CAPPED");
    BOOST_REQUIRE_EQUAL(plane.workers(), 64);
    ExpectQuiet(plane);

    BOOST_REQUIRE(plane.Drain("thermal", err));
    BOOST_REQUIRE_EQUAL(plane.workers(), 0);
    ExpectQuiet(plane);
}

BOOST_AUTO_TEST_SUITE_END()
