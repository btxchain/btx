// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnohf.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_notnohf_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(empty_origin_id_is_origin)
{
    std::string err = "prior";
    modelnet::SwarmNotNoHf note;
    note.want_authority = true;
    const modelnet::SwarmNotNoHfResult result = modelnet::SwarmNoteNotNoHf(note, err);
    BOOST_CHECK(!result.authority);
    BOOST_CHECK(!result.published);
    BOOST_CHECK_EQUAL(result.code, "ORIGIN");
    BOOST_CHECK_EQUAL(err, "ORIGIN");
}

BOOST_AUTO_TEST_CASE(want_authority_is_not_authority)
{
    std::string err = "prior";
    modelnet::SwarmNotNoHf note;
    note.origin_id = "origin-1";
    note.want_authority = true;
    const modelnet::SwarmNotNoHfResult result = modelnet::SwarmNoteNotNoHf(note, err);
    BOOST_CHECK(!result.authority);
    BOOST_CHECK(!result.published);
    BOOST_CHECK_EQUAL(result.code, "NOT_AUTHORITY");
    BOOST_CHECK_EQUAL(err, "NOT_AUTHORITY");
}

BOOST_AUTO_TEST_CASE(plain_note_is_noted)
{
    std::string err = "prior";
    modelnet::SwarmNotNoHf note;
    note.origin_id = "origin-1";
    note.want_authority = false;
    const modelnet::SwarmNotNoHfResult result = modelnet::SwarmNoteNotNoHf(note, err);
    BOOST_CHECK(!result.authority);
    BOOST_CHECK(!result.published);
    BOOST_CHECK_EQUAL(result.code, "NOTED");
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_SUITE_END()
