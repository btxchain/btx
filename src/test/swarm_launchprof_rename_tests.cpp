// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_launchprof/codes.h>
#include <modelnet/swarm_launchprof/limits.h>
#include <modelnet/swarm_launchprof/swarm_launchprofile.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_launchprof_rename_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(stored_rename_leaves_the_profile)
{
    modelnet::SwarmLaunchProfile plane;
    std::string err = "prior";

    BOOST_REQUIRE(!plane.stored("op-a"));
    BOOST_REQUIRE(plane.stored_name("op-a").empty());
    BOOST_REQUIRE(plane.rename_count() == 0);
    BOOST_REQUIRE(plane.profile() == "BTX035-LAUNCH-DECODER-2x64");
    BOOST_REQUIRE(plane.profile() == modelnet::kSwarmLaunchProfileName);
    BOOST_REQUIRE(!plane.renamed());
    BOOST_REQUIRE_EQUAL(plane.bytes_moved(), 0);
    BOOST_REQUIRE(!plane.gpu());
    BOOST_REQUIRE(!plane.launched());

    BOOST_REQUIRE(!plane.Rename("op-a", err));
    BOOST_REQUIRE(err == modelnet::kSwarmLaunchProfileHeld);
    BOOST_REQUIRE_EQUAL(err, "HELD");
    BOOST_REQUIRE(plane.stored("op-a"));
    BOOST_REQUIRE(plane.stored_name("op-a") == "op-a");
    BOOST_REQUIRE(plane.rename_count() == 1);
    BOOST_REQUIRE(plane.profile() == "BTX035-LAUNCH-DECODER-2x64");
    BOOST_REQUIRE(!plane.renamed());
    BOOST_REQUIRE(plane.renamed() == modelnet::kSwarmLaunchProfileRenamed);
    BOOST_REQUIRE_EQUAL(plane.bytes_moved(), 0);
    BOOST_REQUIRE(plane.bytes_moved() == modelnet::kSwarmLaunchProfileBytesMoved);
    BOOST_REQUIRE(!plane.gpu());
    BOOST_REQUIRE(plane.gpu() == modelnet::kSwarmLaunchProfileGpu);
    BOOST_REQUIRE(!plane.launched());
    BOOST_REQUIRE(plane.launched() == modelnet::kSwarmLaunchProfileLaunched);
}

BOOST_AUTO_TEST_CASE(a_second_distinct_name_is_stored_beside_the_first)
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
    BOOST_REQUIRE(!plane.Rename("op-b", err));
    BOOST_REQUIRE(err == modelnet::kSwarmLaunchProfileHeld);
    BOOST_REQUIRE_EQUAL(err, "HELD");
    BOOST_REQUIRE(plane.stored("op-a"));
    BOOST_REQUIRE(plane.stored("op-b"));
    BOOST_REQUIRE(plane.stored_name("op-a") == "op-a");
    BOOST_REQUIRE(plane.stored_name("op-b") == "op-b");
    BOOST_REQUIRE(plane.rename_count() == 2);
    BOOST_REQUIRE(plane.profile() == modelnet::kSwarmLaunchProfileName);
    BOOST_REQUIRE(!plane.renamed());
    BOOST_REQUIRE_EQUAL(plane.bytes_moved(), 0);
    BOOST_REQUIRE(!plane.gpu());
    BOOST_REQUIRE(!plane.launched());
}

BOOST_AUTO_TEST_CASE(space_and_code_word_are_stored_and_the_profile_stays)
{
    modelnet::SwarmLaunchProfile plane;
    std::string err = "prior";

    BOOST_REQUIRE(!plane.Rename(" ", err));
    BOOST_REQUIRE(err == modelnet::kSwarmLaunchProfileHeld);
    BOOST_REQUIRE_EQUAL(err, "HELD");
    BOOST_REQUIRE(plane.stored(" "));
    BOOST_REQUIRE(plane.stored_name(" ") == " ");
    BOOST_REQUIRE(plane.profile() == "BTX035-LAUNCH-DECODER-2x64");
    BOOST_REQUIRE(!plane.renamed());

    err = "prior";
    BOOST_REQUIRE(!plane.Rename("PROFILE", err));
    BOOST_REQUIRE(err == modelnet::kSwarmLaunchProfileHeld);
    BOOST_REQUIRE_EQUAL(err, "HELD");
    BOOST_REQUIRE(plane.stored("PROFILE"));
    BOOST_REQUIRE(plane.stored_name("PROFILE") == "PROFILE");
    BOOST_REQUIRE(plane.stored(" "));
    BOOST_REQUIRE(plane.rename_count() == 2);
    BOOST_REQUIRE(plane.profile() == "BTX035-LAUNCH-DECODER-2x64");
    BOOST_REQUIRE(!plane.renamed());
    BOOST_REQUIRE_EQUAL(plane.bytes_moved(), 0);
    BOOST_REQUIRE(!plane.gpu());
    BOOST_REQUIRE(!plane.launched());
}

BOOST_AUTO_TEST_CASE(renaming_to_the_profile_string_does_not_rename)
{
    modelnet::SwarmLaunchProfile plane;
    std::string err = "prior";

    BOOST_REQUIRE(!plane.Rename("BTX035-LAUNCH-DECODER-2x64", err));
    BOOST_REQUIRE(err == modelnet::kSwarmLaunchProfileHeld);
    BOOST_REQUIRE_EQUAL(err, "HELD");
    BOOST_REQUIRE(plane.stored("BTX035-LAUNCH-DECODER-2x64"));
    BOOST_REQUIRE(plane.stored_name("BTX035-LAUNCH-DECODER-2x64") == "BTX035-LAUNCH-DECODER-2x64");
    BOOST_REQUIRE(plane.rename_count() == 1);
    BOOST_REQUIRE(plane.profile() == "BTX035-LAUNCH-DECODER-2x64");
    BOOST_REQUIRE(plane.profile() == modelnet::kSwarmLaunchProfileName);
    BOOST_REQUIRE(!plane.renamed());
    BOOST_REQUIRE_EQUAL(plane.bytes_moved(), 0);
    BOOST_REQUIRE(!plane.gpu());
    BOOST_REQUIRE(!plane.launched());
}

BOOST_AUTO_TEST_SUITE_END()
