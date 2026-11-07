// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_rescap/codes.h>
#include <modelnet/swarm_rescap/limits.h>
#include <modelnet/swarm_rescap/swarm_rescap.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_rescap_raise_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(one_thread_is_stored_and_stays_unraised)
{
    modelnet::SwarmResCap plane;
    std::string err = "prior";

    BOOST_REQUIRE(!plane.stored(1));
    BOOST_REQUIRE_EQUAL(plane.stored_threads(1), 0);
    BOOST_REQUIRE(plane.raise_count() == 0);
    BOOST_REQUIRE(!plane.raised());
    BOOST_REQUIRE_EQUAL(plane.cap_threads(), 64);
    BOOST_REQUIRE_EQUAL(plane.bytes_moved(), 0);
    BOOST_REQUIRE(!plane.gpu());
    BOOST_REQUIRE(!plane.launched());

    BOOST_REQUIRE(!plane.Raise(1, err));
    BOOST_REQUIRE(err == modelnet::kSwarmResCapCapped);
    BOOST_REQUIRE_EQUAL(err, "CAPPED");
    BOOST_REQUIRE(plane.stored(1));
    BOOST_REQUIRE_EQUAL(plane.stored_threads(1), 1);
    BOOST_REQUIRE(plane.raise_count() == 1);
    BOOST_REQUIRE(!plane.raised());
    BOOST_REQUIRE(plane.raised() == modelnet::kSwarmResCapRaised);
    BOOST_REQUIRE_EQUAL(plane.cap_threads(), 64);
    BOOST_REQUIRE(plane.cap_threads() == modelnet::kSwarmResCapThreadCap);
    BOOST_REQUIRE_EQUAL(plane.bytes_moved(), 0);
    BOOST_REQUIRE(plane.bytes_moved() == modelnet::kSwarmResCapBytesMoved);
    BOOST_REQUIRE(!plane.gpu());
    BOOST_REQUIRE(plane.gpu() == modelnet::kSwarmResCapGpu);
    BOOST_REQUIRE(!plane.launched());
    BOOST_REQUIRE(plane.launched() == modelnet::kSwarmResCapLaunched);
}

BOOST_AUTO_TEST_CASE(the_cap_itself_is_stored_and_the_cap_stays_64)
{
    modelnet::SwarmResCap plane;
    std::string err = "prior";

    BOOST_REQUIRE(!plane.Raise(64, err));
    BOOST_REQUIRE(err == modelnet::kSwarmResCapCapped);
    BOOST_REQUIRE_EQUAL(err, "CAPPED");
    BOOST_REQUIRE(plane.stored(64));
    BOOST_REQUIRE_EQUAL(plane.stored_threads(64), 64);
    BOOST_REQUIRE(plane.raise_count() == 1);
    BOOST_REQUIRE(!plane.raised());
    BOOST_REQUIRE_EQUAL(plane.cap_threads(), 64);
    BOOST_REQUIRE(plane.cap_threads() == modelnet::kSwarmResCapThreadCap);
    BOOST_REQUIRE_EQUAL(plane.bytes_moved(), 0);
    BOOST_REQUIRE(!plane.gpu());
    BOOST_REQUIRE(!plane.launched());
}

BOOST_AUTO_TEST_CASE(a_second_distinct_count_is_stored_beside_the_first)
{
    modelnet::SwarmResCap plane;
    std::string err = "prior";

    BOOST_REQUIRE(!plane.Raise(8, err));
    BOOST_REQUIRE(err == modelnet::kSwarmResCapCapped);
    BOOST_REQUIRE_EQUAL(err, "CAPPED");
    BOOST_REQUIRE(plane.stored(8));
    BOOST_REQUIRE_EQUAL(plane.stored_threads(8), 8);
    BOOST_REQUIRE(!plane.raised());

    err = "prior";
    BOOST_REQUIRE(!plane.Raise(32, err));
    BOOST_REQUIRE(err == modelnet::kSwarmResCapCapped);
    BOOST_REQUIRE_EQUAL(err, "CAPPED");
    BOOST_REQUIRE(plane.stored(8));
    BOOST_REQUIRE(plane.stored(32));
    BOOST_REQUIRE_EQUAL(plane.stored_threads(8), 8);
    BOOST_REQUIRE_EQUAL(plane.stored_threads(32), 32);
    BOOST_REQUIRE(plane.raise_count() == 2);
    BOOST_REQUIRE(!plane.raised());
    BOOST_REQUIRE_EQUAL(plane.cap_threads(), 64);
    BOOST_REQUIRE_EQUAL(plane.bytes_moved(), 0);
    BOOST_REQUIRE(!plane.gpu());
    BOOST_REQUIRE(!plane.launched());
}

BOOST_AUTO_TEST_SUITE_END()
