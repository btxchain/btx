// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_faultboard/swarm_faultboard.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

namespace {

void ExpectIdle(const modelnet::SwarmFaultBoard& plane)
{
    BOOST_CHECK(!plane.launched());
    BOOST_CHECK(!plane.gpu());
    BOOST_CHECK(plane.bytes_moved() == 0);
    BOOST_CHECK(plane.atoms_moved() == 0);
    BOOST_CHECK_EQUAL(plane.automatic_spend(), "0");
    BOOST_CHECK(!plane.broadcast());
    BOOST_CHECK(!plane.mined());
    BOOST_CHECK(!plane.saved());
}

} // namespace

BOOST_FIXTURE_TEST_SUITE(swarm_faultboard_worker_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(keep_result_keeps_the_first_receipt)
{
    modelnet::SwarmFaultBoard plane;
    std::string err = "prior";

    BOOST_REQUIRE(plane.KeepResult("task-a", "receipt-a", err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK(plane.has_result("task-a"));
    BOOST_CHECK_EQUAL(plane.result("task-a"), "receipt-a");

    BOOST_REQUIRE(plane.KeepResult("task-a", "receipt-a", err));
    BOOST_CHECK_EQUAL(plane.result("task-a"), "receipt-a");

    err = "prior";
    BOOST_REQUIRE(!plane.KeepResult("task-a", "receipt-b", err));
    BOOST_REQUIRE_EQUAL(err, "CONFLICT");
    BOOST_CHECK_EQUAL(plane.result("task-a"), "receipt-a");

    BOOST_REQUIRE(plane.KeepResult("task-b", "receipt-b", err));
    BOOST_CHECK_EQUAL(plane.result("task-b"), "receipt-b");
    ExpectIdle(plane);
}

BOOST_AUTO_TEST_CASE(worker_disconnect_keeps_a_result_and_deletes_nothing)
{
    modelnet::SwarmFaultBoard plane;
    std::string err = "prior";

    BOOST_REQUIRE(plane.KeepClaim("task-a", "worker-a", err));
    BOOST_REQUIRE(plane.KeepResult("task-a", "receipt-a", err));

    err = "prior";
    BOOST_REQUIRE(!plane.WorkerDisconnect("task-a", err));
    BOOST_REQUIRE_EQUAL(err, "DISCONNECTED");
    BOOST_CHECK_EQUAL(plane.result("task-a"), "receipt-a");
    BOOST_CHECK_EQUAL(plane.claim("task-a"), "worker-a");
    BOOST_CHECK(plane.claim_count() == 1);

    err = "prior";
    BOOST_REQUIRE(!plane.WorkerDisconnect("task-missing", err));
    BOOST_REQUIRE_EQUAL(err, "DISCONNECTED");
    BOOST_CHECK(!plane.has_result("task-missing"));
    BOOST_CHECK_EQUAL(plane.result("task-missing"), "");
    BOOST_CHECK(plane.claim_count() == 1);
    BOOST_CHECK_EQUAL(plane.result("task-a"), "receipt-a");
    ExpectIdle(plane);
}

BOOST_AUTO_TEST_CASE(duplicate_receipt_distinguishes_replay_conflict_and_unknown)
{
    modelnet::SwarmFaultBoard plane;
    std::string err = "prior";

    BOOST_REQUIRE(plane.KeepClaim("task-claim", "worker-a", err));
    BOOST_REQUIRE(plane.KeepResult("task-a", "receipt-a", err));

    err = "prior";
    BOOST_REQUIRE(!plane.DuplicateReceipt("task-a", "receipt-a", err));
    BOOST_REQUIRE_EQUAL(err, "REPLAY");
    BOOST_CHECK_EQUAL(plane.result("task-a"), "receipt-a");

    err = "prior";
    BOOST_REQUIRE(!plane.DuplicateReceipt("task-a", "receipt-b", err));
    BOOST_REQUIRE_EQUAL(err, "CONFLICT");
    BOOST_CHECK_EQUAL(plane.result("task-a"), "receipt-a");

    err = "prior";
    BOOST_REQUIRE(!plane.DuplicateReceipt("task-missing", "receipt-a", err));
    BOOST_REQUIRE_EQUAL(err, "TASK");
    BOOST_CHECK(!plane.has_result("task-missing"));

    err = "prior";
    BOOST_REQUIRE(!plane.DuplicateReceipt("task-claim", "receipt-a", err));
    BOOST_REQUIRE_EQUAL(err, "TASK");
    BOOST_CHECK(plane.has_claim("task-claim"));
    BOOST_CHECK(!plane.has_result("task-claim"));
    BOOST_CHECK_EQUAL(plane.result("task-a"), "receipt-a");
    ExpectIdle(plane);
}

BOOST_AUTO_TEST_CASE(gpu_crash_holds_the_checkpoint_and_does_not_save)
{
    modelnet::SwarmFaultBoard plane;
    std::string err = "prior";

    BOOST_REQUIRE(!plane.GpuCrash(err));
    BOOST_REQUIRE_EQUAL(err, "SAVE_HELD");
    BOOST_CHECK(!plane.has_checkpoint());
    BOOST_CHECK(!plane.saved());
    BOOST_CHECK(!plane.gpu());
    BOOST_CHECK(!plane.launched());

    BOOST_REQUIRE(plane.KeepCheckpoint("ckpt-a", err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK(plane.has_checkpoint());
    BOOST_CHECK_EQUAL(plane.checkpoint(), "ckpt-a");
    BOOST_CHECK(!plane.saved());

    err = "prior";
    BOOST_REQUIRE(!plane.GpuCrash(err));
    BOOST_REQUIRE_EQUAL(err, "SAVE_HELD");
    BOOST_CHECK_EQUAL(plane.checkpoint(), "ckpt-a");
    BOOST_CHECK(!plane.saved());
    BOOST_CHECK(!plane.gpu());
    BOOST_CHECK(!plane.launched());

    BOOST_REQUIRE(plane.KeepCheckpoint("ckpt-b", err));
    BOOST_CHECK_EQUAL(plane.checkpoint(), "ckpt-b");
    BOOST_CHECK(!plane.saved());

    err = "prior";
    BOOST_REQUIRE(!plane.GpuCrash(err));
    BOOST_CHECK_EQUAL(plane.checkpoint(), "ckpt-b");
    BOOST_CHECK(!plane.saved());
    ExpectIdle(plane);
}

BOOST_AUTO_TEST_SUITE_END()
