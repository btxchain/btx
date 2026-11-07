// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_rescap/codes.h>
#include <modelnet/swarm_rescap/limits.h>
#include <modelnet/swarm_rescap/swarm_rescap.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <cstdint>
#include <limits>
#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_rescap_under_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(threads_below_one_are_cap_and_store_nothing)
{
    modelnet::SwarmResCap plane;
    std::string err = "prior";

    BOOST_REQUIRE(!plane.Raise(0, err));
    BOOST_REQUIRE(err == modelnet::kSwarmResCapCap);
    BOOST_REQUIRE_EQUAL(err, "CAP");
    BOOST_REQUIRE(!plane.stored(0));
    BOOST_REQUIRE_EQUAL(plane.stored_threads(0), 0);
    BOOST_REQUIRE(plane.raise_count() == 0);
    BOOST_REQUIRE(!plane.raised());
    BOOST_REQUIRE(plane.raised() == modelnet::kSwarmResCapRaised);
    BOOST_REQUIRE_EQUAL(plane.cap_threads(), 64);
    BOOST_REQUIRE(plane.cap_threads() == modelnet::kSwarmResCapThreadCap);
    BOOST_REQUIRE_EQUAL(plane.bytes_moved(), 0);
    BOOST_REQUIRE(!plane.gpu());
    BOOST_REQUIRE(!plane.launched());

    err = "prior";
    BOOST_REQUIRE(!plane.Raise(-1, err));
    BOOST_REQUIRE(err == modelnet::kSwarmResCapCap);
    BOOST_REQUIRE_EQUAL(err, "CAP");
    BOOST_REQUIRE(!plane.stored(-1));
    BOOST_REQUIRE(plane.raise_count() == 0);
    BOOST_REQUIRE(!plane.raised());
    BOOST_REQUIRE_EQUAL(plane.cap_threads(), 64);

    err = "prior";
    BOOST_REQUIRE(!plane.Raise(std::numeric_limits<int64_t>::min(), err));
    BOOST_REQUIRE(err == modelnet::kSwarmResCapCap);
    BOOST_REQUIRE_EQUAL(err, "CAP");
    BOOST_REQUIRE(!plane.stored(std::numeric_limits<int64_t>::min()));
    BOOST_REQUIRE(plane.raise_count() == 0);
    BOOST_REQUIRE(!plane.raised());
    BOOST_REQUIRE_EQUAL(plane.cap_threads(), 64);
    BOOST_REQUIRE_EQUAL(plane.bytes_moved(), 0);
    BOOST_REQUIRE(!plane.gpu());
    BOOST_REQUIRE(!plane.launched());

    err = "prior";
    BOOST_REQUIRE(!plane.Raise(0, err));
    BOOST_REQUIRE(err == modelnet::kSwarmResCapCap);
    BOOST_REQUIRE_EQUAL(err, "CAP");
    BOOST_REQUIRE(plane.raise_count() == 0);
    BOOST_REQUIRE(!plane.raised());
    BOOST_REQUIRE_EQUAL(plane.cap_threads(), 64);
}

BOOST_AUTO_TEST_CASE(below_one_after_a_raise_keeps_the_stored_count)
{
    modelnet::SwarmResCap plane;
    std::string err = "prior";

    BOOST_REQUIRE(!plane.Raise(4, err));
    BOOST_REQUIRE(err == modelnet::kSwarmResCapCapped);
    BOOST_REQUIRE_EQUAL(err, "CAPPED");
    BOOST_REQUIRE(plane.stored(4));
    BOOST_REQUIRE_EQUAL(plane.stored_threads(4), 4);
    BOOST_REQUIRE(!plane.raised());

    err = "prior";
    BOOST_REQUIRE(!plane.Raise(0, err));
    BOOST_REQUIRE(err == modelnet::kSwarmResCapCap);
    BOOST_REQUIRE_EQUAL(err, "CAP");
    BOOST_REQUIRE(plane.stored(4));
    BOOST_REQUIRE_EQUAL(plane.stored_threads(4), 4);
    BOOST_REQUIRE(!plane.stored(0));
    BOOST_REQUIRE(plane.raise_count() == 1);
    BOOST_REQUIRE(!plane.raised());
    BOOST_REQUIRE_EQUAL(plane.cap_threads(), 64);
    BOOST_REQUIRE_EQUAL(plane.bytes_moved(), 0);
    BOOST_REQUIRE(!plane.gpu());
    BOOST_REQUIRE(!plane.launched());
}

BOOST_AUTO_TEST_CASE(below_one_does_not_block_a_later_raise)
{
    modelnet::SwarmResCap plane;
    std::string err = "prior";

    BOOST_REQUIRE(!plane.Raise(-8, err));
    BOOST_REQUIRE(err == modelnet::kSwarmResCapCap);
    BOOST_REQUIRE_EQUAL(err, "CAP");
    BOOST_REQUIRE(plane.raise_count() == 0);

    err = "prior";
    BOOST_REQUIRE(!plane.Raise(1, err));
    BOOST_REQUIRE(err == modelnet::kSwarmResCapCapped);
    BOOST_REQUIRE_EQUAL(err, "CAPPED");
    BOOST_REQUIRE(plane.stored(1));
    BOOST_REQUIRE_EQUAL(plane.stored_threads(1), 1);
    BOOST_REQUIRE(plane.raise_count() == 1);
    BOOST_REQUIRE(!plane.raised());
    BOOST_REQUIRE_EQUAL(plane.cap_threads(), 64);
    BOOST_REQUIRE_EQUAL(plane.bytes_moved(), 0);
    BOOST_REQUIRE(!plane.gpu());
    BOOST_REQUIRE(!plane.launched());
}

BOOST_AUTO_TEST_SUITE_END()
