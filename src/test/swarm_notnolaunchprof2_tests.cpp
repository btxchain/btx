// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnolaunchprof2.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_notnolaunchprof2_tests, BasicTestingSetup)

static modelnet::SwarmNotNoLaunchProf2 NotedNote()
{
    modelnet::SwarmNotNoLaunchProf2 note;
    note.profile_id = "BTX035-LAUNCH-DECODER-2x64";
    note.want_rename = false;
    return note;
}

BOOST_AUTO_TEST_CASE(empty_profile_id_is_profile)
{
    modelnet::SwarmNotNoLaunchProf2 note = NotedNote();
    note.profile_id.clear();
    note.want_rename = true;
    std::string err = "prior";
    const modelnet::SwarmNotNoLaunchProf2Result result = modelnet::SwarmNoteNotNoLaunchProf2(note, err);
    BOOST_CHECK(!result.renamed);
    BOOST_CHECK_EQUAL(result.code, "PROFILE");
    BOOST_CHECK_EQUAL(err, "PROFILE");
    BOOST_CHECK(note.profile_id.empty());
}

BOOST_AUTO_TEST_CASE(want_rename_is_held)
{
    modelnet::SwarmNotNoLaunchProf2 note = NotedNote();
    note.want_rename = true;
    std::string err = "prior";
    const modelnet::SwarmNotNoLaunchProf2Result result = modelnet::SwarmNoteNotNoLaunchProf2(note, err);
    BOOST_CHECK(!result.renamed);
    BOOST_CHECK_EQUAL(result.code, "HELD");
    BOOST_CHECK_EQUAL(err, "HELD");
    BOOST_CHECK_EQUAL(note.profile_id, "BTX035-LAUNCH-DECODER-2x64");
}

BOOST_AUTO_TEST_CASE(plain_launch_profile_is_noted)
{
    modelnet::SwarmNotNoLaunchProf2 note = NotedNote();
    note.want_rename = false;
    std::string err = "prior";
    const modelnet::SwarmNotNoLaunchProf2Result result = modelnet::SwarmNoteNotNoLaunchProf2(note, err);
    BOOST_CHECK(!result.renamed);
    BOOST_CHECK_EQUAL(result.code, "NOTED");
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(note.profile_id, "BTX035-LAUNCH-DECODER-2x64");
}

BOOST_AUTO_TEST_SUITE_END()
