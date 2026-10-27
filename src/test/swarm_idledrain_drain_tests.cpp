// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_idledrain/idledrain.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_idledrain_drain_tests, BasicTestingSetup)

static void ExpectDrainThenRefuseAdmit(const char* reason)
{
    modelnet::SwarmIdleDrain plane;
    std::string err = "prior";

    BOOST_REQUIRE(plane.Open(err));
    BOOST_REQUIRE(err.empty());
    BOOST_REQUIRE(plane.Admit(err));
    BOOST_REQUIRE(err.empty());
    BOOST_REQUIRE_EQUAL(plane.workers(), 2);
    BOOST_REQUIRE_EQUAL(plane.bytes_moved(), 0);
    BOOST_REQUIRE(!plane.gpu());
    BOOST_REQUIRE(!plane.launched());

    err = "prior";
    BOOST_REQUIRE(plane.Drain(reason, err));
    BOOST_REQUIRE(err.empty());
    BOOST_REQUIRE(plane.drained());
    BOOST_REQUIRE(plane.opened());
    BOOST_REQUIRE_EQUAL(plane.workers(), 0);

    err = "prior";
    BOOST_REQUIRE(!plane.Admit(err));
    BOOST_REQUIRE_EQUAL(err, "DRAINED");
    BOOST_REQUIRE_EQUAL(plane.workers(), 0);
    BOOST_REQUIRE(plane.drained());
    BOOST_REQUIRE_EQUAL(plane.bytes_moved(), 0);
    BOOST_REQUIRE(!plane.gpu());
    BOOST_REQUIRE(!plane.launched());
}

BOOST_AUTO_TEST_CASE(battery_drains_workers_and_a_later_admit_is_refused)
{
    ExpectDrainThenRefuseAdmit("battery");
}

BOOST_AUTO_TEST_CASE(thermal_drains_workers_and_a_later_admit_is_refused)
{
    ExpectDrainThenRefuseAdmit("thermal");
}

BOOST_AUTO_TEST_CASE(metered_drains_workers_and_a_later_admit_is_refused)
{
    ExpectDrainThenRefuseAdmit("metered");
}

BOOST_AUTO_TEST_CASE(second_drain_of_any_matching_reason_is_replay)
{
    modelnet::SwarmIdleDrain plane;
    std::string err = "prior";

    BOOST_REQUIRE(plane.Open(err));
    BOOST_REQUIRE(plane.Admit(err));
    BOOST_REQUIRE_EQUAL(plane.workers(), 2);

    BOOST_REQUIRE(plane.Drain("battery", err));
    BOOST_REQUIRE(err.empty());
    BOOST_REQUIRE_EQUAL(plane.workers(), 0);

    err = "prior";
    BOOST_REQUIRE(!plane.Drain("battery", err));
    BOOST_REQUIRE_EQUAL(err, "REPLAY");
    BOOST_REQUIRE_EQUAL(plane.workers(), 0);

    err = "prior";
    BOOST_REQUIRE(!plane.Drain("thermal", err));
    BOOST_REQUIRE_EQUAL(err, "REPLAY");
    BOOST_REQUIRE_EQUAL(plane.workers(), 0);

    err = "prior";
    BOOST_REQUIRE(!plane.Drain("metered", err));
    BOOST_REQUIRE_EQUAL(err, "REPLAY");
    BOOST_REQUIRE_EQUAL(plane.workers(), 0);
    BOOST_REQUIRE(plane.drained());
    BOOST_REQUIRE_EQUAL(plane.bytes_moved(), 0);
    BOOST_REQUIRE(!plane.gpu());
    BOOST_REQUIRE(!plane.launched());

    err = "prior";
    BOOST_REQUIRE(!plane.Admit(err));
    BOOST_REQUIRE_EQUAL(err, "DRAINED");
    BOOST_REQUIRE_EQUAL(plane.workers(), 0);
}

BOOST_AUTO_TEST_CASE(thermal_then_metered_is_replay)
{
    modelnet::SwarmIdleDrain plane;
    std::string err = "prior";

    BOOST_REQUIRE(plane.Open(err));
    BOOST_REQUIRE(plane.Drain("thermal", err));
    BOOST_REQUIRE(err.empty());
    BOOST_REQUIRE_EQUAL(plane.workers(), 0);

    err = "prior";
    BOOST_REQUIRE(!plane.Drain("metered", err));
    BOOST_REQUIRE_EQUAL(err, "REPLAY");
    BOOST_REQUIRE_EQUAL(plane.workers(), 0);
    BOOST_REQUIRE(plane.drained());
}

BOOST_AUTO_TEST_CASE(metered_then_battery_is_replay)
{
    modelnet::SwarmIdleDrain plane;
    std::string err = "prior";

    BOOST_REQUIRE(plane.Drain("metered", err));
    BOOST_REQUIRE(err.empty());
    BOOST_REQUIRE_EQUAL(plane.workers(), 0);
    BOOST_REQUIRE(plane.drained());
    BOOST_REQUIRE(!plane.opened());

    err = "prior";
    BOOST_REQUIRE(!plane.Drain("battery", err));
    BOOST_REQUIRE_EQUAL(err, "REPLAY");
    BOOST_REQUIRE_EQUAL(plane.workers(), 0);

    err = "prior";
    BOOST_REQUIRE(!plane.Admit(err));
    BOOST_REQUIRE_EQUAL(err, "DRAINED");
    BOOST_REQUIRE_EQUAL(plane.workers(), 0);
    BOOST_REQUIRE_EQUAL(plane.bytes_moved(), 0);
    BOOST_REQUIRE(!plane.gpu());
    BOOST_REQUIRE(!plane.launched());
}

BOOST_AUTO_TEST_CASE(bad_reason_changes_nothing)
{
    const char* bad[] = {"", "power", "Battery", "battery ", "THERMAL", "meter", "unmetered", "batterythermal"};
    for (const char* reason : bad) {
        modelnet::SwarmIdleDrain plane;
        std::string err = "prior";

        BOOST_REQUIRE(plane.Open(err));
        BOOST_REQUIRE(plane.Admit(err));
        BOOST_REQUIRE_EQUAL(plane.workers(), 2);
        BOOST_REQUIRE(!plane.drained());

        err = "prior";
        BOOST_REQUIRE(!plane.Drain(reason, err));
        BOOST_REQUIRE_EQUAL(err, "REASON");
        BOOST_REQUIRE_EQUAL(plane.workers(), 2);
        BOOST_REQUIRE(plane.opened());
        BOOST_REQUIRE(!plane.drained());
        BOOST_REQUIRE_EQUAL(plane.bytes_moved(), 0);
        BOOST_REQUIRE(!plane.gpu());
        BOOST_REQUIRE(!plane.launched());

        BOOST_REQUIRE(plane.Admit(err));
        BOOST_REQUIRE(err.empty());
        BOOST_REQUIRE_EQUAL(plane.workers(), 3);
        BOOST_REQUIRE(!plane.drained());
    }
}

BOOST_AUTO_TEST_CASE(bad_reason_after_drain_stays_reason)
{
    modelnet::SwarmIdleDrain plane;
    std::string err = "prior";

    BOOST_REQUIRE(plane.Open(err));
    BOOST_REQUIRE(plane.Drain("battery", err));
    BOOST_REQUIRE(err.empty());
    BOOST_REQUIRE_EQUAL(plane.workers(), 0);

    err = "prior";
    BOOST_REQUIRE(!plane.Drain("power", err));
    BOOST_REQUIRE_EQUAL(err, "REASON");
    BOOST_REQUIRE_EQUAL(plane.workers(), 0);
    BOOST_REQUIRE(plane.drained());

    err = "prior";
    BOOST_REQUIRE(!plane.Admit(err));
    BOOST_REQUIRE_EQUAL(err, "DRAINED");
    BOOST_REQUIRE_EQUAL(plane.workers(), 0);
    BOOST_REQUIRE_EQUAL(plane.bytes_moved(), 0);
    BOOST_REQUIRE(!plane.gpu());
    BOOST_REQUIRE(!plane.launched());
}

BOOST_AUTO_TEST_CASE(second_open_after_drain_leaves_zero)
{
    modelnet::SwarmIdleDrain plane;
    std::string err = "prior";

    BOOST_REQUIRE(plane.Open(err));
    BOOST_REQUIRE(plane.Admit(err));
    BOOST_REQUIRE_EQUAL(plane.workers(), 2);
    BOOST_REQUIRE(plane.Drain("metered", err));
    BOOST_REQUIRE_EQUAL(plane.workers(), 0);

    err = "prior";
    BOOST_REQUIRE(!plane.Open(err));
    BOOST_REQUIRE_EQUAL(err, "REPLAY");
    BOOST_REQUIRE_EQUAL(plane.workers(), 0);
    BOOST_REQUIRE(plane.drained());

    err = "prior";
    BOOST_REQUIRE(!plane.Admit(err));
    BOOST_REQUIRE_EQUAL(err, "DRAINED");
    BOOST_REQUIRE_EQUAL(plane.workers(), 0);
    BOOST_REQUIRE_EQUAL(plane.bytes_moved(), 0);
    BOOST_REQUIRE(!plane.gpu());
    BOOST_REQUIRE(!plane.launched());
}

BOOST_AUTO_TEST_SUITE_END()
