// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnoid.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_notnoid_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(empty_identity_id_is_identity)
{
    std::string err = "prior";
    modelnet::SwarmNotNoId note;
    note.want_grant = true;
    const modelnet::SwarmNotNoIdResult result = modelnet::SwarmNoteNotNoId(note, err);
    BOOST_CHECK(!result.granted);
    BOOST_CHECK(!result.bytes_moved);
    BOOST_CHECK_EQUAL(result.code, "IDENTITY");
    BOOST_CHECK_EQUAL(err, "IDENTITY");
}

BOOST_AUTO_TEST_CASE(want_grant_is_not_grant)
{
    std::string err = "prior";
    modelnet::SwarmNotNoId note;
    note.identity_id = "identity-1";
    note.want_grant = true;
    const modelnet::SwarmNotNoIdResult result = modelnet::SwarmNoteNotNoId(note, err);
    BOOST_CHECK(!result.granted);
    BOOST_CHECK(!result.bytes_moved);
    BOOST_CHECK_EQUAL(result.code, "NOT_GRANT");
    BOOST_CHECK_EQUAL(err, "NOT_GRANT");
}

BOOST_AUTO_TEST_CASE(plain_note_is_noted)
{
    std::string err = "prior";
    modelnet::SwarmNotNoId note;
    note.identity_id = "identity-1";
    note.want_grant = false;
    const modelnet::SwarmNotNoIdResult result = modelnet::SwarmNoteNotNoId(note, err);
    BOOST_CHECK(!result.granted);
    BOOST_CHECK(!result.bytes_moved);
    BOOST_CHECK_EQUAL(result.code, "NOTED");
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_SUITE_END()
