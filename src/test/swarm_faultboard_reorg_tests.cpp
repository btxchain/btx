// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_faultboard/swarm_faultboard.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <cstdint>
#include <string>

namespace {

void ExpectQuiet(const modelnet::SwarmFaultBoard& plane)
{
    BOOST_CHECK(!plane.broadcast());
    BOOST_CHECK(!plane.mined());
    BOOST_CHECK(plane.bytes_moved() == 0);
    BOOST_CHECK(plane.atoms_moved() == 0);
    BOOST_CHECK_EQUAL(plane.automatic_spend(), "0");
    BOOST_CHECK(!plane.launched());
    BOOST_CHECK(!plane.gpu());
    BOOST_CHECK(!plane.saved());
}

} // namespace

BOOST_FIXTURE_TEST_SUITE(swarm_faultboard_reorg_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(reserve_before_reorg_stores_one_amount)
{
    modelnet::SwarmFaultBoard plane;
    std::string err = "prior";

    BOOST_REQUIRE(!plane.Reserve(0, err));
    BOOST_REQUIRE_EQUAL(err, "COLLATERAL");
    BOOST_CHECK(!plane.has_reservation());
    BOOST_CHECK(plane.reservation() == 0);

    err = "prior";
    BOOST_REQUIRE(!plane.Reserve(int64_t{-4}, err));
    BOOST_REQUIRE_EQUAL(err, "COLLATERAL");
    BOOST_CHECK(!plane.has_reservation());

    BOOST_REQUIRE(plane.Reserve(7, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK(plane.has_reservation());
    BOOST_CHECK(plane.reservation() == 7);
    BOOST_CHECK(!plane.frozen());

    err = "prior";
    BOOST_REQUIRE(!plane.Reserve(9, err));
    BOOST_REQUIRE_EQUAL(err, "COLLATERAL_REUSE");
    BOOST_CHECK(plane.reservation() == 7);

    err = "prior";
    BOOST_REQUIRE(!plane.Reserve(0, err));
    BOOST_REQUIRE_EQUAL(err, "COLLATERAL_REUSE");
    BOOST_CHECK(plane.reservation() == 7);
    ExpectQuiet(plane);
}

BOOST_AUTO_TEST_CASE(reorg_freezes_and_later_reserve_stores_nothing)
{
    modelnet::SwarmFaultBoard plane;
    std::string err = "prior";

    BOOST_REQUIRE(plane.KeepEarned("work-a", 20, err));
    BOOST_REQUIRE(plane.KeepClaim("task-a", "worker-a", err));
    BOOST_REQUIRE(plane.Reserve(5, err));

    err = "prior";
    BOOST_REQUIRE(!plane.Reorg(err));
    BOOST_REQUIRE_EQUAL(err, "FREEZE");
    BOOST_CHECK(plane.frozen());
    BOOST_CHECK(plane.reservation() == 5);
    BOOST_CHECK(plane.earned_count() == 1);
    BOOST_CHECK(plane.earned("work-a") == 20);
    BOOST_CHECK(plane.claim_count() == 1);

    err = "prior";
    BOOST_REQUIRE(!plane.Reserve(11, err));
    BOOST_REQUIRE_EQUAL(err, "FROZEN");
    BOOST_CHECK(plane.reservation() == 5);
    BOOST_CHECK(plane.frozen());

    err = "prior";
    BOOST_REQUIRE(!plane.Reserve(0, err));
    BOOST_REQUIRE_EQUAL(err, "FROZEN");
    BOOST_CHECK(plane.reservation() == 5);

    err = "prior";
    BOOST_REQUIRE(!plane.Reorg(err));
    BOOST_REQUIRE_EQUAL(err, "FREEZE");
    BOOST_CHECK(plane.frozen());
    BOOST_CHECK(plane.earned("work-a") == 20);
    ExpectQuiet(plane);
}

BOOST_AUTO_TEST_CASE(reserve_after_reorg_with_nothing_stored_is_frozen)
{
    modelnet::SwarmFaultBoard plane;
    std::string err = "prior";

    BOOST_REQUIRE(plane.KeepEarned("work-a", 1, err));
    err = "prior";
    BOOST_REQUIRE(!plane.Reorg(err));
    BOOST_REQUIRE_EQUAL(err, "FREEZE");
    BOOST_CHECK(plane.frozen());
    BOOST_CHECK(!plane.has_reservation());

    err = "prior";
    BOOST_REQUIRE(!plane.Reserve(3, err));
    BOOST_REQUIRE_EQUAL(err, "FROZEN");
    BOOST_CHECK(!plane.has_reservation());
    BOOST_CHECK(plane.reservation() == 0);
    BOOST_CHECK(plane.earned_count() == 1);
    BOOST_CHECK(plane.earned("work-a") == 1);
    ExpectQuiet(plane);
}

BOOST_AUTO_TEST_CASE(double_collateral_stores_once)
{
    modelnet::SwarmFaultBoard plane;
    std::string err = "prior";

    BOOST_REQUIRE(!plane.DoubleCollateral(0, err));
    BOOST_REQUIRE_EQUAL(err, "COLLATERAL");
    BOOST_CHECK(!plane.has_reservation());

    err = "prior";
    BOOST_REQUIRE(!plane.DoubleCollateral(int64_t{-2}, err));
    BOOST_REQUIRE_EQUAL(err, "COLLATERAL");
    BOOST_CHECK(!plane.has_reservation());

    BOOST_REQUIRE(plane.DoubleCollateral(4, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK(plane.reservation() == 4);

    err = "prior";
    BOOST_REQUIRE(!plane.DoubleCollateral(8, err));
    BOOST_REQUIRE_EQUAL(err, "COLLATERAL_REUSE");
    BOOST_CHECK(plane.reservation() == 4);

    err = "prior";
    BOOST_REQUIRE(!plane.DoubleCollateral(0, err));
    BOOST_REQUIRE_EQUAL(err, "COLLATERAL_REUSE");
    BOOST_CHECK(plane.reservation() == 4);

    err = "prior";
    BOOST_REQUIRE(!plane.DoubleCollateral(1, err));
    BOOST_REQUIRE_EQUAL(err, "COLLATERAL_REUSE");
    BOOST_CHECK(plane.has_reservation());
    BOOST_CHECK(plane.reservation() == 4);
    ExpectQuiet(plane);
}

BOOST_AUTO_TEST_CASE(reserve_and_double_collateral_share_one_slot)
{
    modelnet::SwarmFaultBoard reserved;
    std::string err = "prior";
    BOOST_REQUIRE(reserved.Reserve(6, err));
    err = "prior";
    BOOST_REQUIRE(!reserved.DoubleCollateral(9, err));
    BOOST_REQUIRE_EQUAL(err, "COLLATERAL_REUSE");
    BOOST_CHECK(reserved.reservation() == 6);

    modelnet::SwarmFaultBoard doubled;
    BOOST_REQUIRE(doubled.DoubleCollateral(6, err));
    err = "prior";
    BOOST_REQUIRE(!doubled.Reserve(9, err));
    BOOST_REQUIRE_EQUAL(err, "COLLATERAL_REUSE");
    BOOST_CHECK(doubled.reservation() == 6);
    BOOST_CHECK(!doubled.frozen());
    ExpectQuiet(doubled);
}

BOOST_AUTO_TEST_CASE(double_collateral_after_reorg_can_still_store_once)
{
    modelnet::SwarmFaultBoard plane;
    std::string err = "prior";

    BOOST_REQUIRE(plane.KeepEarned("work-a", 2, err));
    err = "prior";
    BOOST_REQUIRE(!plane.Reorg(err));
    BOOST_CHECK(plane.frozen());

    BOOST_REQUIRE(plane.DoubleCollateral(3, err));
    BOOST_CHECK(plane.reservation() == 3);
    BOOST_CHECK(plane.frozen());
    BOOST_CHECK(plane.earned("work-a") == 2);

    err = "prior";
    BOOST_REQUIRE(!plane.DoubleCollateral(1, err));
    BOOST_REQUIRE_EQUAL(err, "COLLATERAL_REUSE");
    BOOST_CHECK(plane.reservation() == 3);

    err = "prior";
    BOOST_REQUIRE(!plane.Reserve(3, err));
    BOOST_REQUIRE_EQUAL(err, "FROZEN");
    BOOST_CHECK(plane.reservation() == 3);
    ExpectQuiet(plane);
}

BOOST_AUTO_TEST_SUITE_END()
