// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnoprof.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_notnoprof_tests, BasicTestingSetup)

static modelnet::SwarmNotNoProf NotedNote()
{
    modelnet::SwarmNotNoProf note;
    note.profile_id = "BTX035-LAUNCH-DECODER-2x64";
    note.want_change = false;
    return note;
}

BOOST_AUTO_TEST_CASE(empty_profile_id_is_profile)
{
    modelnet::SwarmNotNoProf note = NotedNote();
    note.profile_id.clear();
    note.want_change = true;
    std::string err = "prior";
    const modelnet::SwarmNotNoProfResult result = modelnet::SwarmNoteNotNoProf(note, err);
    BOOST_CHECK(!result.changed);
    BOOST_CHECK(!result.launched);
    BOOST_CHECK_EQUAL(result.code, "PROFILE");
    BOOST_CHECK_EQUAL(err, "PROFILE");
    BOOST_CHECK(note.profile_id.empty());
}

BOOST_AUTO_TEST_CASE(other_profile_without_want_change_is_fixed)
{
    modelnet::SwarmNotNoProf note = NotedNote();
    note.profile_id = "other-profile";
    note.want_change = false;
    std::string err = "prior";
    const modelnet::SwarmNotNoProfResult result = modelnet::SwarmNoteNotNoProf(note, err);
    BOOST_CHECK(!result.changed);
    BOOST_CHECK(!result.launched);
    BOOST_CHECK_EQUAL(result.code, "FIXED");
    BOOST_CHECK_EQUAL(err, "FIXED");
    BOOST_CHECK_EQUAL(note.profile_id, "other-profile");
}

BOOST_AUTO_TEST_CASE(want_change_on_fixed_profile_is_fixed)
{
    modelnet::SwarmNotNoProf note = NotedNote();
    note.want_change = true;
    std::string err = "prior";
    const modelnet::SwarmNotNoProfResult result = modelnet::SwarmNoteNotNoProf(note, err);
    BOOST_CHECK(!result.changed);
    BOOST_CHECK(!result.launched);
    BOOST_CHECK_EQUAL(result.code, "FIXED");
    BOOST_CHECK_EQUAL(err, "FIXED");
    BOOST_CHECK_EQUAL(note.profile_id, "BTX035-LAUNCH-DECODER-2x64");
}

BOOST_AUTO_TEST_CASE(plain_fixed_profile_is_noted)
{
    modelnet::SwarmNotNoProf note = NotedNote();
    note.want_change = false;
    std::string err = "prior";
    const modelnet::SwarmNotNoProfResult result = modelnet::SwarmNoteNotNoProf(note, err);
    BOOST_CHECK(!result.changed);
    BOOST_CHECK(!result.launched);
    BOOST_CHECK_EQUAL(result.code, "NOTED");
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(note.profile_id, "BTX035-LAUNCH-DECODER-2x64");
}

BOOST_AUTO_TEST_SUITE_END()
