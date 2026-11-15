// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_holdrot/codes.h>
#include <modelnet/swarm_holdrot/limits.h>
#include <modelnet/swarm_holdrot/swarm_holdrot.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_holdrot_empty_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(empty_rotate_is_holdout_and_stores_nothing)
{
    modelnet::SwarmHoldoutRotate plane;
    std::string err = "prior";

    BOOST_REQUIRE(!plane.Rotate("", err));
    BOOST_REQUIRE(err == modelnet::kSwarmHoldoutRotateHoldout);
    BOOST_REQUIRE_EQUAL(err, "HOLDOUT");
    BOOST_REQUIRE(!plane.held(""));
    BOOST_REQUIRE(plane.stored_holdout("").empty());
    BOOST_REQUIRE(plane.holdout_count() == 0);
    BOOST_REQUIRE(!plane.rotated());
    BOOST_REQUIRE(plane.rotated() == modelnet::kSwarmHoldoutRotateRotated);
    BOOST_REQUIRE_EQUAL(plane.bytes_moved(), 0);
    BOOST_REQUIRE(!plane.gpu());
    BOOST_REQUIRE(!plane.launched());

    err = "prior";
    BOOST_REQUIRE(!plane.Rotate("", err));
    BOOST_REQUIRE(err == modelnet::kSwarmHoldoutRotateHoldout);
    BOOST_REQUIRE_EQUAL(err, "HOLDOUT");
    BOOST_REQUIRE(plane.holdout_count() == 0);
    BOOST_REQUIRE(!plane.rotated());
    BOOST_REQUIRE_EQUAL(plane.bytes_moved(), 0);
}

BOOST_AUTO_TEST_CASE(empty_holdout_leaves_a_stored_holdout_in_place)
{
    modelnet::SwarmHoldoutRotate plane;
    std::string err = "prior";

    BOOST_REQUIRE(!plane.Rotate("fold-a", err));
    BOOST_REQUIRE(err == modelnet::kSwarmHoldoutRotateNotRotating);
    BOOST_REQUIRE_EQUAL(err, "NOT_ROTATING");
    BOOST_REQUIRE(plane.held("fold-a"));
    BOOST_REQUIRE(plane.stored_holdout("fold-a") == "fold-a");
    BOOST_REQUIRE(!plane.rotated());

    err = "prior";
    BOOST_REQUIRE(!plane.Rotate("", err));
    BOOST_REQUIRE(err == modelnet::kSwarmHoldoutRotateHoldout);
    BOOST_REQUIRE_EQUAL(err, "HOLDOUT");
    BOOST_REQUIRE(plane.held("fold-a"));
    BOOST_REQUIRE(plane.stored_holdout("fold-a") == "fold-a");
    BOOST_REQUIRE(!plane.held(""));
    BOOST_REQUIRE(plane.holdout_count() == 1);
    BOOST_REQUIRE(!plane.rotated());
    BOOST_REQUIRE_EQUAL(plane.bytes_moved(), 0);
    BOOST_REQUIRE(!plane.gpu());
    BOOST_REQUIRE(!plane.launched());
}

BOOST_AUTO_TEST_SUITE_END()
