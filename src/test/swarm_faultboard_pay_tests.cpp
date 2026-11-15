// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_faultboard/swarm_faultboard.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <cstdint>
#include <string>

namespace {

void ExpectUnpaid(const modelnet::SwarmFaultBoard& plane)
{
    BOOST_CHECK(plane.atoms_moved() == 0);
    BOOST_CHECK(plane.bytes_moved() == 0);
    BOOST_CHECK_EQUAL(plane.automatic_spend(), "0");
    BOOST_CHECK(!plane.broadcast());
    BOOST_CHECK(!plane.mined());
    BOOST_CHECK(!plane.saved());
    BOOST_CHECK(!plane.launched());
    BOOST_CHECK(!plane.gpu());
}

} // namespace

BOOST_FIXTURE_TEST_SUITE(swarm_faultboard_pay_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(keep_earned_stores_non_negative_atoms_without_moving_them)
{
    modelnet::SwarmFaultBoard plane;
    std::string err = "prior";

    BOOST_REQUIRE(plane.KeepEarned("work-zero", 0, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK(plane.has_earned("work-zero"));
    BOOST_CHECK(plane.earned("work-zero") == 0);
    BOOST_CHECK(plane.earned_count() == 1);
    BOOST_CHECK(plane.atoms_moved() == 0);

    BOOST_REQUIRE(plane.KeepEarned("work-zero", 0, err));
    BOOST_CHECK(plane.earned_count() == 1);

    err = "prior";
    BOOST_REQUIRE(!plane.KeepEarned("work-zero", 5, err));
    BOOST_REQUIRE_EQUAL(err, "CONFLICT");
    BOOST_CHECK(plane.earned("work-zero") == 0);
    BOOST_CHECK(plane.earned_count() == 1);

    err = "prior";
    BOOST_REQUIRE(!plane.KeepEarned("work-neg", int64_t{-1}, err));
    BOOST_REQUIRE_EQUAL(err, "ATOMS");
    BOOST_CHECK(!plane.has_earned("work-neg"));
    BOOST_CHECK(plane.earned_count() == 1);

    BOOST_REQUIRE(plane.KeepEarned("work-max", INT64_MAX, err));
    BOOST_CHECK(plane.earned("work-max") == INT64_MAX);
    BOOST_CHECK(plane.earned_count() == 2);
    BOOST_CHECK(plane.atoms_moved() == 0);
    ExpectUnpaid(plane);
}

BOOST_AUTO_TEST_CASE(pay_crash_holds_an_existing_row_and_creates_nothing)
{
    modelnet::SwarmFaultBoard plane;
    std::string err = "prior";

    BOOST_REQUIRE(plane.KeepEarned("work-a", 12, err));
    err = "prior";
    BOOST_REQUIRE(!plane.PayCrash("work-a", err));
    BOOST_REQUIRE_EQUAL(err, "HELD");
    BOOST_CHECK(plane.has_earned("work-a"));
    BOOST_CHECK(plane.earned("work-a") == 12);
    BOOST_CHECK(plane.earned_count() == 1);
    BOOST_CHECK(plane.atoms_moved() == 0);

    err = "prior";
    BOOST_REQUIRE(!plane.PayCrash("work-missing", err));
    BOOST_REQUIRE_EQUAL(err, "HELD");
    BOOST_CHECK(!plane.has_earned("work-missing"));
    BOOST_CHECK(plane.earned_count() == 1);
    BOOST_CHECK(plane.earned("work-a") == 12);
    ExpectUnpaid(plane);
}

BOOST_AUTO_TEST_CASE(refund_mature_is_broadcast_forbidden)
{
    modelnet::SwarmFaultBoard plane;
    std::string err = "prior";

    BOOST_REQUIRE(plane.KeepEarned("work-a", 4, err));
    err = "prior";
    BOOST_REQUIRE(!plane.RefundMature(err));
    BOOST_REQUIRE_EQUAL(err, "BROADCAST_FORBIDDEN");
    BOOST_CHECK(!plane.broadcast());
    BOOST_CHECK(!plane.mined());
    BOOST_CHECK_EQUAL(plane.automatic_spend(), "0");
    BOOST_CHECK(plane.earned_count() == 1);
    BOOST_CHECK(plane.earned("work-a") == 4);
    BOOST_CHECK(plane.atoms_moved() == 0);
    ExpectUnpaid(plane);
}

BOOST_AUTO_TEST_CASE(earned_row_is_never_deleted)
{
    modelnet::SwarmFaultBoard plane;
    std::string err;

    BOOST_REQUIRE(plane.KeepClaim("task-a", "worker-a", err));
    BOOST_REQUIRE(plane.KeepResult("task-a", "receipt-a", err));
    BOOST_REQUIRE(plane.KeepEarned("work-a", 15, err));
    BOOST_REQUIRE(plane.KeepEarned("work-b", 0, err));
    BOOST_REQUIRE(plane.KeepHead("channel-a", "head-live", err));
    BOOST_REQUIRE(plane.KeepCheckpoint("ckpt-a", err));

    BOOST_REQUIRE(!plane.CoordinatorGone(err));
    BOOST_REQUIRE(!plane.GpuCrash(err));
    BOOST_REQUIRE(!plane.WorkerDisconnect("task-a", err));
    BOOST_REQUIRE(!plane.DuplicateReceipt("task-a", "receipt-other", err));
    BOOST_REQUIRE(!plane.CacheOwnerGone(err));
    BOOST_REQUIRE(!plane.TruncatedCache(err));
    BOOST_REQUIRE(!plane.PartialPiece(err));
    BOOST_REQUIRE(!plane.PromotionInterrupted("channel-a", err));
    BOOST_REQUIRE(!plane.CanaryRegress("channel-a", "", err));
    BOOST_REQUIRE(!plane.CanaryRegress("channel-a", "head-prev", err));
    BOOST_REQUIRE(!plane.ConflictingReports(err));
    BOOST_REQUIRE(!plane.PayCrash("work-a", err));
    BOOST_REQUIRE(!plane.PayCrash("work-missing", err));
    BOOST_REQUIRE(!plane.RefundMature(err));
    BOOST_REQUIRE(!plane.Reorg(err));
    BOOST_REQUIRE(!plane.RevokedRead(err));
    BOOST_REQUIRE(!plane.DatasetWithdrawn(err));
    BOOST_REQUIRE(!plane.FalseCompat(err));
    BOOST_REQUIRE(!plane.PermanentGone(err));
    BOOST_REQUIRE_EQUAL(err, "DURABLE");

    BOOST_CHECK(plane.earned_count() == 2);
    BOOST_CHECK(plane.has_earned("work-a"));
    BOOST_CHECK(plane.has_earned("work-b"));
    BOOST_CHECK(plane.earned("work-a") == 15);
    BOOST_CHECK(plane.earned("work-b") == 0);
    BOOST_CHECK(plane.claim_count() == 1);
    BOOST_CHECK_EQUAL(plane.result("task-a"), "receipt-a");
    BOOST_CHECK_EQUAL(plane.checkpoint(), "ckpt-a");
    BOOST_CHECK(plane.atoms_moved() == 0);
    BOOST_CHECK(!plane.saved());
    BOOST_CHECK(plane.frozen());
    ExpectUnpaid(plane);
}

BOOST_AUTO_TEST_SUITE_END()
