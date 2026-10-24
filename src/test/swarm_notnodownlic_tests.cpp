// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnodownlic.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_notnodownlic_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(empty_license_id_is_license)
{
    modelnet::SwarmNotNoDownLic note;
    note.download_only = true;
    note.want_train = true;
    std::string err = "prior";
    const modelnet::SwarmNotNoDownLicResult result = modelnet::SwarmNoteNotNoDownLic(note, err);
    BOOST_CHECK(!result.trained);
    BOOST_CHECK(!result.bytes_moved);
    BOOST_CHECK_EQUAL(result.code, "LICENSE");
    BOOST_CHECK_EQUAL(err, "LICENSE");
}

BOOST_AUTO_TEST_CASE(download_only_is_not_grant_when_want_train_is_false)
{
    modelnet::SwarmNotNoDownLic note;
    note.license_id = "license-1";
    note.download_only = true;
    note.want_train = false;
    std::string err = "prior";
    const modelnet::SwarmNotNoDownLicResult result = modelnet::SwarmNoteNotNoDownLic(note, err);
    BOOST_CHECK(!result.trained);
    BOOST_CHECK(!result.bytes_moved);
    BOOST_CHECK_EQUAL(result.code, "NOT_GRANT");
    BOOST_CHECK_EQUAL(err, "NOT_GRANT");
}

BOOST_AUTO_TEST_CASE(want_train_is_not_grant)
{
    modelnet::SwarmNotNoDownLic note;
    note.license_id = "license-1";
    note.download_only = false;
    note.want_train = true;
    std::string err = "prior";
    const modelnet::SwarmNotNoDownLicResult result = modelnet::SwarmNoteNotNoDownLic(note, err);
    BOOST_CHECK(!result.trained);
    BOOST_CHECK(!result.bytes_moved);
    BOOST_CHECK_EQUAL(result.code, "NOT_GRANT");
    BOOST_CHECK_EQUAL(err, "NOT_GRANT");
}

BOOST_AUTO_TEST_CASE(plain_note_is_noted)
{
    modelnet::SwarmNotNoDownLic note;
    note.license_id = "license-1";
    note.download_only = false;
    note.want_train = false;
    std::string err = "prior";
    const modelnet::SwarmNotNoDownLicResult result = modelnet::SwarmNoteNotNoDownLic(note, err);
    BOOST_CHECK(!result.trained);
    BOOST_CHECK(!result.bytes_moved);
    BOOST_CHECK_EQUAL(result.code, "NOTED");
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_SUITE_END()
