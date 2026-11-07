// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnoprivatefam.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_notnoprivatefam_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(empty_family_id)
{
    std::string err = "prior";
    modelnet::SwarmNotNoPrivateFam note;
    note.private_family = true;
    note.want_publish = true;
    const modelnet::SwarmNotNoPrivateFamResult result = modelnet::SwarmNoteNotNoPrivateFam(note, err);
    BOOST_CHECK(!result.published);
    BOOST_CHECK(!result.bytes_moved);
    BOOST_CHECK_EQUAL(result.code, "FAMILY");
    BOOST_CHECK_EQUAL(err, "FAMILY");
}

BOOST_AUTO_TEST_CASE(private_family)
{
    std::string err = "prior";
    modelnet::SwarmNotNoPrivateFam note;
    note.family_id = "family-1";
    note.private_family = true;
    note.want_publish = false;
    const modelnet::SwarmNotNoPrivateFamResult result = modelnet::SwarmNoteNotNoPrivateFam(note, err);
    BOOST_CHECK(!result.published);
    BOOST_CHECK(!result.bytes_moved);
    BOOST_CHECK_EQUAL(result.code, "REFUSED");
    BOOST_CHECK_EQUAL(err, "REFUSED");
}

BOOST_AUTO_TEST_CASE(want_publish)
{
    std::string err = "prior";
    modelnet::SwarmNotNoPrivateFam note;
    note.family_id = "family-1";
    note.private_family = false;
    note.want_publish = true;
    const modelnet::SwarmNotNoPrivateFamResult result = modelnet::SwarmNoteNotNoPrivateFam(note, err);
    BOOST_CHECK(!result.published);
    BOOST_CHECK(!result.bytes_moved);
    BOOST_CHECK_EQUAL(result.code, "REFUSED");
    BOOST_CHECK_EQUAL(err, "REFUSED");
}

BOOST_AUTO_TEST_CASE(plain_note)
{
    std::string err = "prior";
    modelnet::SwarmNotNoPrivateFam note;
    note.family_id = "family-1";
    note.private_family = false;
    note.want_publish = false;
    const modelnet::SwarmNotNoPrivateFamResult result = modelnet::SwarmNoteNotNoPrivateFam(note, err);
    BOOST_CHECK(!result.published);
    BOOST_CHECK(!result.bytes_moved);
    BOOST_CHECK_EQUAL(result.code, "NOTED");
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_SUITE_END()
