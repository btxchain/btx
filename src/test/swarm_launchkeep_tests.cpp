// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_launchkeep.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_launchkeep_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(empty_profile_id)
{
    modelnet::SwarmLaunchKeep profile;
    profile.profile_id.clear();
    profile.want_rename = false;
    std::string err;
    const modelnet::SwarmLaunchKeepResult result = modelnet::SwarmKeepLaunchProfile(profile, err);
    BOOST_CHECK(!result.renamed);
    BOOST_CHECK_EQUAL(result.profile, "BTX035-LAUNCH-DECODER-2x64");
    BOOST_CHECK_EQUAL(result.code, "PROFILE");
    BOOST_CHECK_EQUAL(err, "PROFILE");
}

BOOST_AUTO_TEST_CASE(want_rename_held)
{
    modelnet::SwarmLaunchKeep profile;
    profile.profile_id = "BTX035-LAUNCH-DECODER-2x64";
    profile.want_rename = true;
    std::string err;
    const modelnet::SwarmLaunchKeepResult result = modelnet::SwarmKeepLaunchProfile(profile, err);
    BOOST_CHECK(!result.renamed);
    BOOST_CHECK_EQUAL(result.profile, "BTX035-LAUNCH-DECODER-2x64");
    BOOST_CHECK_EQUAL(result.code, "HELD");
    BOOST_CHECK_EQUAL(err, "HELD");
}

BOOST_AUTO_TEST_CASE(noted)
{
    modelnet::SwarmLaunchKeep profile;
    profile.profile_id = "BTX035-LAUNCH-DECODER-2x64";
    profile.want_rename = false;
    std::string err = "stale";
    const modelnet::SwarmLaunchKeepResult result = modelnet::SwarmKeepLaunchProfile(profile, err);
    BOOST_CHECK(!result.renamed);
    BOOST_CHECK_EQUAL(result.profile, "BTX035-LAUNCH-DECODER-2x64");
    BOOST_CHECK_EQUAL(result.code, "NOTED");
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_SUITE_END()
