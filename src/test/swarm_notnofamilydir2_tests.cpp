// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnofamilydir2.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_notnofamilydir2_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(empty_directory_id)
{
    std::string err = "prior";
    modelnet::SwarmNotNoFamilyDir2 note;
    note.want_publish = true;
    const modelnet::SwarmNotNoFamilyDir2Result result = modelnet::SwarmNoteNotNoFamilyDir2(note, err);
    BOOST_CHECK(!result.published);
    BOOST_CHECK_EQUAL(result.code, "DIRECTORY");
    BOOST_CHECK_EQUAL(err, "DIRECTORY");
}

BOOST_AUTO_TEST_CASE(want_publish)
{
    std::string err = "prior";
    modelnet::SwarmNotNoFamilyDir2 note;
    note.directory_id = "directory-1";
    note.want_publish = true;
    const modelnet::SwarmNotNoFamilyDir2Result result = modelnet::SwarmNoteNotNoFamilyDir2(note, err);
    BOOST_CHECK(!result.published);
    BOOST_CHECK_EQUAL(result.code, "HELD");
    BOOST_CHECK_EQUAL(err, "HELD");
}

BOOST_AUTO_TEST_CASE(plain_note)
{
    std::string err = "prior";
    modelnet::SwarmNotNoFamilyDir2 note;
    note.directory_id = "directory-1";
    note.want_publish = false;
    const modelnet::SwarmNotNoFamilyDir2Result result = modelnet::SwarmNoteNotNoFamilyDir2(note, err);
    BOOST_CHECK(!result.published);
    BOOST_CHECK_EQUAL(result.code, "NOTED");
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_SUITE_END()
