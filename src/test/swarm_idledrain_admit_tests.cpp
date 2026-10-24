// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_idledrain/idledrain.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_idledrain_admit_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(admit_before_drain_increments)
{
    modelnet::SwarmIdleDrain plane;
    std::string err = "prior";

    BOOST_REQUIRE(plane.Open(err));
    BOOST_REQUIRE(err.empty());
    BOOST_REQUIRE_EQUAL(plane.workers(), 1);

    BOOST_REQUIRE(plane.Admit(err));
    BOOST_REQUIRE(err.empty());
    BOOST_REQUIRE_EQUAL(plane.workers(), 2);
    BOOST_REQUIRE(!plane.drained());

    BOOST_REQUIRE(plane.Admit(err));
    BOOST_REQUIRE(err.empty());
    BOOST_REQUIRE_EQUAL(plane.workers(), 3);
    BOOST_REQUIRE(plane.opened());
    BOOST_REQUIRE_EQUAL(plane.bytes_moved(), 0);
    BOOST_REQUIRE(!plane.gpu());
    BOOST_REQUIRE(!plane.launched());
}

BOOST_AUTO_TEST_CASE(admit_before_open_increments_from_zero)
{
    modelnet::SwarmIdleDrain plane;
    std::string err = "prior";

    BOOST_REQUIRE_EQUAL(plane.workers(), 0);
    BOOST_REQUIRE(plane.Admit(err));
    BOOST_REQUIRE(err.empty());
    BOOST_REQUIRE_EQUAL(plane.workers(), 1);
    BOOST_REQUIRE(!plane.opened());
    BOOST_REQUIRE(!plane.drained());

    BOOST_REQUIRE(plane.Admit(err));
    BOOST_REQUIRE(err.empty());
    BOOST_REQUIRE_EQUAL(plane.workers(), 2);
    BOOST_REQUIRE_EQUAL(plane.bytes_moved(), 0);
    BOOST_REQUIRE(!plane.gpu());
    BOOST_REQUIRE(!plane.launched());
}

BOOST_AUTO_TEST_CASE(admit_after_drain_is_drained)
{
    modelnet::SwarmIdleDrain plane;
    std::string err = "prior";

    BOOST_REQUIRE(plane.Open(err));
    BOOST_REQUIRE(plane.Admit(err));
    BOOST_REQUIRE_EQUAL(plane.workers(), 2);

    BOOST_REQUIRE(plane.Drain("battery", err));
    BOOST_REQUIRE(err.empty());
    BOOST_REQUIRE_EQUAL(plane.workers(), 0);
    BOOST_REQUIRE(plane.drained());

    err = "prior";
    BOOST_REQUIRE(!plane.Admit(err));
    BOOST_REQUIRE_EQUAL(err, "DRAINED");
    BOOST_REQUIRE_EQUAL(plane.workers(), 0);
    BOOST_REQUIRE(plane.drained());
    BOOST_REQUIRE(plane.opened());

    err = "prior";
    BOOST_REQUIRE(!plane.Admit(err));
    BOOST_REQUIRE_EQUAL(err, "DRAINED");
    BOOST_REQUIRE_EQUAL(plane.workers(), 0);
    BOOST_REQUIRE_EQUAL(plane.bytes_moved(), 0);
    BOOST_REQUIRE(!plane.gpu());
    BOOST_REQUIRE(!plane.launched());
}

BOOST_AUTO_TEST_SUITE_END()
