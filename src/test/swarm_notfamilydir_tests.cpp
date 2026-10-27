// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notfamilydir.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_notfamilydir_tests, BasicTestingSetup)

static modelnet::SwarmNotFamilyDir NotedNote()
{
    modelnet::SwarmNotFamilyDir note;
    note.family_id = "family-1";
    note.want_publish = false;
    return note;
}

BOOST_AUTO_TEST_CASE(empty_family_id_is_family)
{
    modelnet::SwarmNotFamilyDir note = NotedNote();
    note.family_id.clear();
    note.want_publish = true;
    std::string err = "prior";
    const modelnet::SwarmNotFamilyDirResult result = modelnet::SwarmNoteNotFamilyDir(note, err);
    BOOST_CHECK(!result.published);
    BOOST_CHECK(!result.global_dir);
    BOOST_CHECK_EQUAL(result.code, "FAMILY");
    BOOST_CHECK_EQUAL(err, "FAMILY");
}

BOOST_AUTO_TEST_CASE(want_publish_is_not_published)
{
    modelnet::SwarmNotFamilyDir note = NotedNote();
    note.want_publish = true;
    std::string err = "prior";
    const modelnet::SwarmNotFamilyDirResult result = modelnet::SwarmNoteNotFamilyDir(note, err);
    BOOST_CHECK(!result.published);
    BOOST_CHECK(!result.global_dir);
    BOOST_CHECK_EQUAL(result.code, "NOT_PUBLISHED");
    BOOST_CHECK_EQUAL(err, "NOT_PUBLISHED");
}

BOOST_AUTO_TEST_CASE(plain_note_is_noted)
{
    modelnet::SwarmNotFamilyDir note = NotedNote();
    note.want_publish = false;
    std::string err = "prior";
    const modelnet::SwarmNotFamilyDirResult result = modelnet::SwarmNoteNotFamilyDir(note, err);
    BOOST_CHECK(!result.published);
    BOOST_CHECK(!result.global_dir);
    BOOST_CHECK_EQUAL(result.code, "NOTED");
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_SUITE_END()
