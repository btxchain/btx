// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_launchprof.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_launchprof_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(empty_profile_is_profile)
{
    std::string err = "prior";
    modelnet::SwarmLaunchProf note;
    note.want_change = true;
    const modelnet::SwarmLaunchProfResult result = modelnet::SwarmNoteLaunchProf(note, err);
    BOOST_CHECK(!result.changed);
    BOOST_CHECK_EQUAL(result.code, "PROFILE");
    BOOST_CHECK_EQUAL(err, "PROFILE");
}

BOOST_AUTO_TEST_CASE(different_profile_with_want_change_is_fixed)
{
    std::string err = "prior";
    modelnet::SwarmLaunchProf note;
    note.profile = "BTX035-LAUNCH-DECODER-OTHER";
    note.want_change = true;
    const modelnet::SwarmLaunchProfResult result = modelnet::SwarmNoteLaunchProf(note, err);
    BOOST_CHECK(!result.changed);
    BOOST_CHECK_EQUAL(result.code, "FIXED");
    BOOST_CHECK_EQUAL(err, "FIXED");
}

BOOST_AUTO_TEST_CASE(exact_profile_with_want_change_is_held)
{
    std::string err = "prior";
    modelnet::SwarmLaunchProf note;
    note.profile = "BTX035-LAUNCH-DECODER-2x64";
    note.want_change = true;
    const modelnet::SwarmLaunchProfResult result = modelnet::SwarmNoteLaunchProf(note, err);
    BOOST_CHECK(!result.changed);
    BOOST_CHECK_EQUAL(result.code, "HELD");
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_CASE(exact_profile_without_want_change_is_noted)
{
    std::string err = "prior";
    modelnet::SwarmLaunchProf note;
    note.profile = "BTX035-LAUNCH-DECODER-2x64";
    note.want_change = false;
    const modelnet::SwarmLaunchProfResult result = modelnet::SwarmNoteLaunchProf(note, err);
    BOOST_CHECK(!result.changed);
    BOOST_CHECK_EQUAL(result.code, "NOTED");
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_SUITE_END()
