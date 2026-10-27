// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_holdrot/codes.h>
#include <modelnet/swarm_holdrot/limits.h>
#include <modelnet/swarm_holdrot/swarm_holdrot.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_holdrot_rotate_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(stored_holdout_stays_not_rotating)
{
    modelnet::SwarmHoldoutRotate plane;
    std::string err = "prior";

    BOOST_REQUIRE(!plane.held("fold-a"));
    BOOST_REQUIRE(plane.stored_holdout("fold-a").empty());
    BOOST_REQUIRE(plane.holdout_count() == 0);
    BOOST_REQUIRE(!plane.rotated());
    BOOST_REQUIRE_EQUAL(plane.bytes_moved(), 0);
    BOOST_REQUIRE(!plane.gpu());
    BOOST_REQUIRE(!plane.launched());

    BOOST_REQUIRE(!plane.Rotate("fold-a", err));
    BOOST_REQUIRE(err == modelnet::kSwarmHoldoutRotateNotRotating);
    BOOST_REQUIRE_EQUAL(err, "NOT_ROTATING");
    BOOST_REQUIRE(plane.held("fold-a"));
    BOOST_REQUIRE(plane.stored_holdout("fold-a") == "fold-a");
    BOOST_REQUIRE(plane.holdout_count() == 1);
    BOOST_REQUIRE(!plane.rotated());
    BOOST_REQUIRE(plane.rotated() == modelnet::kSwarmHoldoutRotateRotated);
    BOOST_REQUIRE_EQUAL(plane.bytes_moved(), 0);
    BOOST_REQUIRE(plane.bytes_moved() == modelnet::kSwarmHoldoutRotateBytesMoved);
    BOOST_REQUIRE(!plane.gpu());
    BOOST_REQUIRE(plane.gpu() == modelnet::kSwarmHoldoutRotateGpu);
    BOOST_REQUIRE(!plane.launched());
    BOOST_REQUIRE(plane.launched() == modelnet::kSwarmHoldoutRotateLaunched);
}

BOOST_AUTO_TEST_CASE(a_second_distinct_holdout_is_stored_beside_the_first)
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
    BOOST_REQUIRE(!plane.Rotate("fold-b", err));
    BOOST_REQUIRE(err == modelnet::kSwarmHoldoutRotateNotRotating);
    BOOST_REQUIRE_EQUAL(err, "NOT_ROTATING");
    BOOST_REQUIRE(plane.held("fold-a"));
    BOOST_REQUIRE(plane.held("fold-b"));
    BOOST_REQUIRE(plane.stored_holdout("fold-a") == "fold-a");
    BOOST_REQUIRE(plane.stored_holdout("fold-b") == "fold-b");
    BOOST_REQUIRE(plane.holdout_count() == 2);
    BOOST_REQUIRE(!plane.rotated());
    BOOST_REQUIRE_EQUAL(plane.bytes_moved(), 0);
    BOOST_REQUIRE(!plane.gpu());
    BOOST_REQUIRE(!plane.launched());
}

BOOST_AUTO_TEST_CASE(space_and_code_word_are_stored_and_stay_not_rotating)
{
    modelnet::SwarmHoldoutRotate plane;
    std::string err = "prior";

    BOOST_REQUIRE(!plane.Rotate(" ", err));
    BOOST_REQUIRE(err == modelnet::kSwarmHoldoutRotateNotRotating);
    BOOST_REQUIRE_EQUAL(err, "NOT_ROTATING");
    BOOST_REQUIRE(plane.held(" "));
    BOOST_REQUIRE(plane.stored_holdout(" ") == " ");
    BOOST_REQUIRE(!plane.rotated());

    err = "prior";
    BOOST_REQUIRE(!plane.Rotate("HOLDOUT", err));
    BOOST_REQUIRE(err == modelnet::kSwarmHoldoutRotateNotRotating);
    BOOST_REQUIRE_EQUAL(err, "NOT_ROTATING");
    BOOST_REQUIRE(plane.held("HOLDOUT"));
    BOOST_REQUIRE(plane.stored_holdout("HOLDOUT") == "HOLDOUT");
    BOOST_REQUIRE(plane.held(" "));
    BOOST_REQUIRE(plane.holdout_count() == 2);
    BOOST_REQUIRE(!plane.rotated());
    BOOST_REQUIRE_EQUAL(plane.bytes_moved(), 0);
    BOOST_REQUIRE(!plane.gpu());
    BOOST_REQUIRE(!plane.launched());
}

BOOST_AUTO_TEST_SUITE_END()
