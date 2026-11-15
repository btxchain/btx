// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_launchprof/codes.h>
#include <modelnet/swarm_launchprof/limits.h>
#include <modelnet/swarm_launchprof/swarm_launchprofile.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_launchprof_empty_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(empty_rename_is_profile_and_stores_nothing)
{
    modelnet::SwarmLaunchProfile plane;
    std::string err = "prior";

    BOOST_REQUIRE(!plane.Rename("", err));
    BOOST_REQUIRE(err == modelnet::kSwarmLaunchProfileProfile);
    BOOST_REQUIRE_EQUAL(err, "PROFILE");
    BOOST_REQUIRE(!plane.stored(""));
    BOOST_REQUIRE(plane.stored_name("").empty());
    BOOST_REQUIRE(plane.rename_count() == 0);
    BOOST_REQUIRE(plane.profile() == "BTX035-LAUNCH-DECODER-2x64");
    BOOST_REQUIRE(plane.profile() == modelnet::kSwarmLaunchProfileName);
    BOOST_REQUIRE(!plane.profile().empty());
    BOOST_REQUIRE(!plane.renamed());
    BOOST_REQUIRE(plane.renamed() == modelnet::kSwarmLaunchProfileRenamed);
    BOOST_REQUIRE_EQUAL(plane.bytes_moved(), 0);
    BOOST_REQUIRE(!plane.gpu());
    BOOST_REQUIRE(!plane.launched());

    err = "prior";
    BOOST_REQUIRE(!plane.Rename("", err));
    BOOST_REQUIRE(err == modelnet::kSwarmLaunchProfileProfile);
    BOOST_REQUIRE_EQUAL(err, "PROFILE");
    BOOST_REQUIRE(plane.rename_count() == 0);
    BOOST_REQUIRE(plane.profile() == "BTX035-LAUNCH-DECODER-2x64");
    BOOST_REQUIRE(!plane.renamed());
    BOOST_REQUIRE_EQUAL(plane.bytes_moved(), 0);
}

BOOST_AUTO_TEST_CASE(empty_name_leaves_a_stored_rename_in_place)
{
    modelnet::SwarmLaunchProfile plane;
    std::string err = "prior";

    BOOST_REQUIRE(!plane.Rename("op-a", err));
    BOOST_REQUIRE(err == modelnet::kSwarmLaunchProfileHeld);
    BOOST_REQUIRE_EQUAL(err, "HELD");
    BOOST_REQUIRE(plane.stored("op-a"));
    BOOST_REQUIRE(plane.stored_name("op-a") == "op-a");
    BOOST_REQUIRE(plane.profile() == "BTX035-LAUNCH-DECODER-2x64");
    BOOST_REQUIRE(!plane.renamed());

    err = "prior";
    BOOST_REQUIRE(!plane.Rename("", err));
    BOOST_REQUIRE(err == modelnet::kSwarmLaunchProfileProfile);
    BOOST_REQUIRE_EQUAL(err, "PROFILE");
    BOOST_REQUIRE(plane.stored("op-a"));
    BOOST_REQUIRE(plane.stored_name("op-a") == "op-a");
    BOOST_REQUIRE(!plane.stored(""));
    BOOST_REQUIRE(plane.rename_count() == 1);
    BOOST_REQUIRE(plane.profile() == modelnet::kSwarmLaunchProfileName);
    BOOST_REQUIRE(!plane.renamed());
    BOOST_REQUIRE_EQUAL(plane.bytes_moved(), 0);
    BOOST_REQUIRE(!plane.gpu());
    BOOST_REQUIRE(!plane.launched());
}

BOOST_AUTO_TEST_SUITE_END()
