// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnoredist2.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_notnoredist2_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(empty_license_id_is_license)
{
    std::string err = "prior";
    modelnet::SwarmNotNoRedist2 note;
    const modelnet::SwarmNotNoRedist2Result result = modelnet::SwarmNoteNotNoRedist2(note, err);
    BOOST_CHECK(!result.granted);
    BOOST_CHECK_EQUAL(result.code, "LICENSE");
    BOOST_CHECK_EQUAL(err, "LICENSE");
}

BOOST_AUTO_TEST_CASE(download_true_want_grant_false_is_not_redist)
{
    std::string err = "prior";
    modelnet::SwarmNotNoRedist2 note;
    note.license_id = "license-1";
    note.download = true;
    note.want_grant = false;
    const modelnet::SwarmNotNoRedist2Result result = modelnet::SwarmNoteNotNoRedist2(note, err);
    BOOST_CHECK(!result.granted);
    BOOST_CHECK_EQUAL(result.code, "NOT_REDIST");
    BOOST_CHECK_EQUAL(err, "NOT_REDIST");
}

BOOST_AUTO_TEST_CASE(want_grant_true_download_false_is_held)
{
    std::string err = "prior";
    modelnet::SwarmNotNoRedist2 note;
    note.license_id = "license-1";
    note.download = false;
    note.want_grant = true;
    const modelnet::SwarmNotNoRedist2Result result = modelnet::SwarmNoteNotNoRedist2(note, err);
    BOOST_CHECK(!result.granted);
    BOOST_CHECK_EQUAL(result.code, "HELD");
    BOOST_CHECK_EQUAL(err, "HELD");
}

BOOST_AUTO_TEST_CASE(neither_is_noted)
{
    std::string err = "prior";
    modelnet::SwarmNotNoRedist2 note;
    note.license_id = "license-1";
    note.download = false;
    note.want_grant = false;
    const modelnet::SwarmNotNoRedist2Result result = modelnet::SwarmNoteNotNoRedist2(note, err);
    BOOST_CHECK(!result.granted);
    BOOST_CHECK_EQUAL(result.code, "NOTED");
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_SUITE_END()
