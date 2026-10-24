// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_idledrain/idledrain.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_idledrain_cap_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(admit_stops_at_64_after_open)
{
    modelnet::SwarmIdleDrain plane;
    std::string err = "prior";

    BOOST_REQUIRE(plane.Open(err));
    BOOST_REQUIRE(err.empty());
    BOOST_REQUIRE_EQUAL(plane.workers(), 1);

    for (int i = 0; i < 63; ++i) {
        BOOST_REQUIRE(plane.Admit(err));
        BOOST_REQUIRE(err.empty());
    }
    BOOST_REQUIRE_EQUAL(plane.workers(), 64);
    BOOST_REQUIRE(!plane.drained());

    err = "prior";
    BOOST_REQUIRE(!plane.Admit(err));
    BOOST_REQUIRE_EQUAL(err, "CAPPED");
    BOOST_REQUIRE_EQUAL(plane.workers(), 64);

    err = "prior";
    BOOST_REQUIRE(!plane.Admit(err));
    BOOST_REQUIRE_EQUAL(err, "CAPPED");
    BOOST_REQUIRE_EQUAL(plane.workers(), 64);
    BOOST_REQUIRE(plane.opened());
    BOOST_REQUIRE(!plane.drained());
    BOOST_REQUIRE_EQUAL(plane.bytes_moved(), 0);
    BOOST_REQUIRE(!plane.gpu());
    BOOST_REQUIRE(!plane.launched());
}

BOOST_AUTO_TEST_CASE(admit_stops_at_64_without_open)
{
    modelnet::SwarmIdleDrain plane;
    std::string err = "prior";

    for (int i = 0; i < 64; ++i) {
        BOOST_REQUIRE(plane.Admit(err));
        BOOST_REQUIRE(err.empty());
    }
    BOOST_REQUIRE_EQUAL(plane.workers(), 64);
    BOOST_REQUIRE(!plane.opened());

    err = "prior";
    BOOST_REQUIRE(!plane.Admit(err));
    BOOST_REQUIRE_EQUAL(err, "CAPPED");
    BOOST_REQUIRE_EQUAL(plane.workers(), 64);
    BOOST_REQUIRE(!plane.drained());
    BOOST_REQUIRE_EQUAL(plane.bytes_moved(), 0);
    BOOST_REQUIRE(!plane.gpu());
    BOOST_REQUIRE(!plane.launched());
}

BOOST_AUTO_TEST_CASE(cap_does_not_block_a_later_drain)
{
    modelnet::SwarmIdleDrain plane;
    std::string err = "prior";

    BOOST_REQUIRE(plane.Open(err));
    for (int i = 0; i < 63; ++i) {
        BOOST_REQUIRE(plane.Admit(err));
    }
    BOOST_REQUIRE_EQUAL(plane.workers(), 64);
    BOOST_REQUIRE(!plane.Admit(err));
    BOOST_REQUIRE_EQUAL(err, "CAPPED");

    BOOST_REQUIRE(plane.Drain("thermal", err));
    BOOST_REQUIRE(err.empty());
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
