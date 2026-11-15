// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_faultboard/swarm_faultboard.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

namespace {

void ExpectBytesHeld(const modelnet::SwarmFaultBoard& plane)
{
    BOOST_CHECK(plane.bytes_moved() == 0);
    BOOST_CHECK(plane.atoms_moved() == 0);
    BOOST_CHECK(!plane.launched());
    BOOST_CHECK(!plane.gpu());
    BOOST_CHECK(!plane.saved());
    BOOST_CHECK(!plane.broadcast());
    BOOST_CHECK(!plane.mined());
    BOOST_CHECK_EQUAL(plane.automatic_spend(), "0");
}

} // namespace

BOOST_FIXTURE_TEST_SUITE(swarm_faultboard_cache_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(cache_owner_gone_is_held)
{
    modelnet::SwarmFaultBoard plane;
    std::string err = "prior";

    BOOST_REQUIRE(plane.KeepCheckpoint("ckpt-a", err));
    err = "prior";
    BOOST_REQUIRE(!plane.CacheOwnerGone(err));
    BOOST_REQUIRE_EQUAL(err, "HELD");
    BOOST_CHECK_EQUAL(plane.checkpoint(), "ckpt-a");
    ExpectBytesHeld(plane);
}

BOOST_AUTO_TEST_CASE(truncated_cache_is_incomplete)
{
    modelnet::SwarmFaultBoard plane;
    std::string err = "prior";

    BOOST_REQUIRE(plane.KeepResult("task-a", "receipt-a", err));
    err = "prior";
    BOOST_REQUIRE(!plane.TruncatedCache(err));
    BOOST_REQUIRE_EQUAL(err, "INCOMPLETE");
    BOOST_CHECK_EQUAL(plane.result("task-a"), "receipt-a");
    ExpectBytesHeld(plane);
}

BOOST_AUTO_TEST_CASE(partial_piece_is_piece)
{
    modelnet::SwarmFaultBoard plane;
    std::string err = "prior";

    BOOST_REQUIRE(!plane.PartialPiece(err));
    BOOST_REQUIRE_EQUAL(err, "PIECE");
    ExpectBytesHeld(plane);
}

BOOST_AUTO_TEST_CASE(revoked_read_is_not_read)
{
    modelnet::SwarmFaultBoard plane;
    std::string err = "prior";

    BOOST_REQUIRE(plane.KeepEarned("work-a", 4, err));
    err = "prior";
    BOOST_REQUIRE(!plane.RevokedRead(err));
    BOOST_REQUIRE_EQUAL(err, "NOT_READ");
    BOOST_CHECK(plane.earned_count() == 1);
    BOOST_CHECK(plane.earned("work-a") == 4);
    BOOST_CHECK(plane.atoms_moved() == 0);
    ExpectBytesHeld(plane);
}

BOOST_AUTO_TEST_CASE(cache_refusals_leave_bytes_at_zero)
{
    modelnet::SwarmFaultBoard plane;
    std::string err;

    BOOST_REQUIRE(!plane.CacheOwnerGone(err));
    BOOST_REQUIRE(!plane.TruncatedCache(err));
    BOOST_REQUIRE(!plane.PartialPiece(err));
    BOOST_REQUIRE(!plane.RevokedRead(err));
    BOOST_CHECK(plane.bytes_moved() == 0);
    BOOST_CHECK_EQUAL(err, "NOT_READ");
    ExpectBytesHeld(plane);
}

BOOST_AUTO_TEST_SUITE_END()
