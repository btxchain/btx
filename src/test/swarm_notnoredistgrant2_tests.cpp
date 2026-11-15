// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnoredistgrant2.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_notnoredistgrant2_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(empty_license_id_is_license)
{
    modelnet::SwarmNotNoRedistGrant2 note;
    note.download = true;
    note.want_share = true;
    std::string err = "prior";
    const modelnet::SwarmNotNoRedistGrant2Result result = modelnet::SwarmNoteNotNoRedistGrant2(note, err);
    BOOST_CHECK(!result.shared);
    BOOST_CHECK_EQUAL(result.code, "LICENSE");
    BOOST_CHECK_EQUAL(err, "LICENSE");
}

BOOST_AUTO_TEST_CASE(download_is_not_shared_when_want_share_is_false)
{
    modelnet::SwarmNotNoRedistGrant2 note;
    note.license_id = "license-1";
    note.download = true;
    note.want_share = false;
    std::string err = "prior";
    const modelnet::SwarmNotNoRedistGrant2Result result = modelnet::SwarmNoteNotNoRedistGrant2(note, err);
    BOOST_CHECK(!result.shared);
    BOOST_CHECK_EQUAL(result.code, "NOT_SHARED");
    BOOST_CHECK_EQUAL(err, "NOT_SHARED");
}

BOOST_AUTO_TEST_CASE(want_share_is_held)
{
    modelnet::SwarmNotNoRedistGrant2 note;
    note.license_id = "license-1";
    note.download = false;
    note.want_share = true;
    std::string err = "prior";
    const modelnet::SwarmNotNoRedistGrant2Result result = modelnet::SwarmNoteNotNoRedistGrant2(note, err);
    BOOST_CHECK(!result.shared);
    BOOST_CHECK_EQUAL(result.code, "HELD");
    BOOST_CHECK_EQUAL(err, "HELD");
}

BOOST_AUTO_TEST_CASE(quiet_note_is_noted)
{
    modelnet::SwarmNotNoRedistGrant2 note;
    note.license_id = "license-1";
    note.download = false;
    note.want_share = false;
    std::string err = "prior";
    const modelnet::SwarmNotNoRedistGrant2Result result = modelnet::SwarmNoteNotNoRedistGrant2(note, err);
    BOOST_CHECK(!result.shared);
    BOOST_CHECK_EQUAL(result.code, "NOTED");
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_SUITE_END()
