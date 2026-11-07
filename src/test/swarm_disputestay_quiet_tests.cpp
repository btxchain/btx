// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_disputestay/limits.h>
#include <modelnet/swarm_disputestay/swarm_disputestay.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

namespace {

void RequireStill(const modelnet::SwarmDisputeStay& plane)
{
    BOOST_REQUIRE(!plane.settled());
    BOOST_REQUIRE(plane.settled() == modelnet::kSwarmDisputeStaySettled);
    BOOST_REQUIRE_EQUAL(plane.atoms_moved(), 0);
    BOOST_REQUIRE(plane.atoms_moved() == modelnet::kSwarmDisputeStayAtomsMoved);
    BOOST_REQUIRE(!plane.broadcast());
    BOOST_REQUIRE(plane.broadcast() == modelnet::kSwarmDisputeStayBroadcast);
    BOOST_REQUIRE(!plane.mined());
    BOOST_REQUIRE(plane.mined() == modelnet::kSwarmDisputeStayMined);
    BOOST_REQUIRE_EQUAL(plane.bytes_moved(), 0);
    BOOST_REQUIRE(plane.bytes_moved() == modelnet::kSwarmDisputeStayBytesMoved);
    BOOST_REQUIRE_EQUAL(plane.automatic_spend(), "0");
    BOOST_REQUIRE_EQUAL(plane.automatic_spend(), modelnet::kSwarmDisputeStayAutomaticSpend);
}

} // namespace

BOOST_FIXTURE_TEST_SUITE(swarm_disputestay_quiet_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(broadcast_mined_bytes_and_spend_stay_fixed)
{
    modelnet::SwarmDisputeStay plane;
    std::string err = "prior";

    RequireStill(plane);

    BOOST_REQUIRE(!plane.Open("", err));
    BOOST_REQUIRE_EQUAL(err, "DISPUTE");
    RequireStill(plane);

    err = "prior";
    BOOST_REQUIRE(plane.Open("dispute-1", err));
    BOOST_REQUIRE(err.empty());
    BOOST_REQUIRE(plane.opened("dispute-1"));
    BOOST_REQUIRE(plane.stored_id("dispute-1") == "dispute-1");
    BOOST_REQUIRE(plane.open_count() == 1);
    RequireStill(plane);

    err = "prior";
    BOOST_REQUIRE(!plane.Open("dispute-1", err));
    BOOST_REQUIRE_EQUAL(err, "REPLAY");
    BOOST_REQUIRE(plane.stored_id("dispute-1") == "dispute-1");
    BOOST_REQUIRE(plane.open_count() == 1);
    RequireStill(plane);

    err = "prior";
    BOOST_REQUIRE(!plane.Settle("dispute-1", 0, err));
    BOOST_REQUIRE_EQUAL(err, "HELD");
    BOOST_REQUIRE(plane.stored_id("dispute-1") == "dispute-1");
    RequireStill(plane);

    err = "prior";
    BOOST_REQUIRE(!plane.Settle("dispute-1", 7, err));
    BOOST_REQUIRE_EQUAL(err, "HELD");
    BOOST_REQUIRE(plane.stored_id("dispute-1") == "dispute-1");
    RequireStill(plane);

    err = "prior";
    BOOST_REQUIRE(!plane.Settle("missing", 3, err));
    BOOST_REQUIRE_EQUAL(err, "HELD");
    BOOST_REQUIRE(!plane.opened("missing"));
    BOOST_REQUIRE(plane.open_count() == 1);
    RequireStill(plane);

    err = "prior";
    BOOST_REQUIRE(!plane.Settle("", 1, err));
    BOOST_REQUIRE_EQUAL(err, "DISPUTE");
    BOOST_REQUIRE(plane.stored_id("dispute-1") == "dispute-1");
    BOOST_REQUIRE(plane.open_count() == 1);
    RequireStill(plane);

    err = "prior";
    BOOST_REQUIRE(plane.Open("dispute-2", err));
    BOOST_REQUIRE(err.empty());
    BOOST_REQUIRE(plane.stored_id("dispute-2") == "dispute-2");
    BOOST_REQUIRE(plane.open_count() == 2);
    RequireStill(plane);
}

BOOST_AUTO_TEST_SUITE_END()
