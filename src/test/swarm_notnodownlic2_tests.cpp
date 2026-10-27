// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnodownlic2.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_notnodownlic2_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(empty_license_id_is_license)
{
    modelnet::SwarmNotNoDownLic2 note;
    note.download = true;
    note.want_train = true;
    note.want_redistribute = true;
    std::string err = "prior";
    const modelnet::SwarmNotNoDownLic2Result result = modelnet::SwarmNoteNotNoDownLic2(note, err);
    BOOST_CHECK(!result.trained);
    BOOST_CHECK(!result.redistributed);
    BOOST_CHECK_EQUAL(result.code, "LICENSE");
    BOOST_CHECK_EQUAL(err, "LICENSE");
}

BOOST_AUTO_TEST_CASE(download_is_not_grant_when_both_wants_are_false)
{
    modelnet::SwarmNotNoDownLic2 note;
    note.license_id = "license-1";
    note.download = true;
    note.want_train = false;
    note.want_redistribute = false;
    std::string err = "prior";
    const modelnet::SwarmNotNoDownLic2Result result = modelnet::SwarmNoteNotNoDownLic2(note, err);
    BOOST_CHECK(!result.trained);
    BOOST_CHECK(!result.redistributed);
    BOOST_CHECK_EQUAL(result.code, "NOT_GRANT");
    BOOST_CHECK_EQUAL(err, "NOT_GRANT");
}

BOOST_AUTO_TEST_CASE(want_train_with_download_true_is_not_grant)
{
    modelnet::SwarmNotNoDownLic2 note;
    note.license_id = "license-1";
    note.download = true;
    note.want_train = true;
    note.want_redistribute = false;
    std::string err = "prior";
    const modelnet::SwarmNotNoDownLic2Result result = modelnet::SwarmNoteNotNoDownLic2(note, err);
    BOOST_CHECK(!result.trained);
    BOOST_CHECK(!result.redistributed);
    BOOST_CHECK_EQUAL(result.code, "NOT_GRANT");
    BOOST_CHECK_EQUAL(err, "NOT_GRANT");
}

BOOST_AUTO_TEST_CASE(quiet_note_with_download_false_is_noted)
{
    modelnet::SwarmNotNoDownLic2 note;
    note.license_id = "license-1";
    note.download = false;
    note.want_train = false;
    note.want_redistribute = false;
    std::string err = "prior";
    const modelnet::SwarmNotNoDownLic2Result result = modelnet::SwarmNoteNotNoDownLic2(note, err);
    BOOST_CHECK(!result.trained);
    BOOST_CHECK(!result.redistributed);
    BOOST_CHECK_EQUAL(result.code, "NOTED");
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_SUITE_END()
