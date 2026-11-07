// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notredistrib.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_notredistrib_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(empty_license_id_is_license)
{
    std::string err = "prior";
    modelnet::SwarmNotRedistrib note;
    note.want_redistribute = true;
    const modelnet::SwarmNotRedistribResult result = modelnet::SwarmNoteNotRedistrib(note, err);
    BOOST_CHECK(!result.granted);
    BOOST_CHECK(!result.bytes_moved);
    BOOST_CHECK_EQUAL(result.code, "LICENSE");
    BOOST_CHECK_EQUAL(err, "LICENSE");
}

BOOST_AUTO_TEST_CASE(want_redistribute_is_not_grant)
{
    std::string err = "prior";
    modelnet::SwarmNotRedistrib note;
    note.license_id = "license-1";
    note.want_redistribute = true;
    const modelnet::SwarmNotRedistribResult result = modelnet::SwarmNoteNotRedistrib(note, err);
    BOOST_CHECK(!result.granted);
    BOOST_CHECK(!result.bytes_moved);
    BOOST_CHECK_EQUAL(result.code, "NOT_GRANT");
    BOOST_CHECK_EQUAL(err, "NOT_GRANT");
}

BOOST_AUTO_TEST_CASE(plain_note_is_noted)
{
    std::string err = "prior";
    modelnet::SwarmNotRedistrib note;
    note.license_id = "license-1";
    note.want_redistribute = false;
    const modelnet::SwarmNotRedistribResult result = modelnet::SwarmNoteNotRedistrib(note, err);
    BOOST_CHECK(!result.granted);
    BOOST_CHECK(!result.bytes_moved);
    BOOST_CHECK_EQUAL(result.code, "NOTED");
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_SUITE_END()
