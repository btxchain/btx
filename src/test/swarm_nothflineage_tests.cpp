// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_nothflineage.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_nothflineage_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(empty_origin_id)
{
    modelnet::SwarmNotHfLineage note;
    note.want_authority = true;
    std::string err = "prior";
    const modelnet::SwarmNotHfLineageResult result = modelnet::SwarmNoteNotHfLineage(note, err);
    BOOST_CHECK_EQUAL(result.code, "ORIGIN");
    BOOST_CHECK(!result.authority);
    BOOST_CHECK(!result.published);
    BOOST_CHECK_EQUAL(err, "ORIGIN");
}

BOOST_AUTO_TEST_CASE(want_authority)
{
    modelnet::SwarmNotHfLineage note;
    note.origin_id = "origin-1";
    note.want_authority = true;
    std::string err = "prior";
    const modelnet::SwarmNotHfLineageResult result = modelnet::SwarmNoteNotHfLineage(note, err);
    BOOST_CHECK_EQUAL(result.code, "NOT_AUTHORITY");
    BOOST_CHECK(!result.authority);
    BOOST_CHECK(!result.published);
    BOOST_CHECK_EQUAL(err, "NOT_AUTHORITY");
}

BOOST_AUTO_TEST_CASE(noted)
{
    modelnet::SwarmNotHfLineage note;
    note.origin_id = "origin-1";
    std::string err = "prior";
    const modelnet::SwarmNotHfLineageResult result = modelnet::SwarmNoteNotHfLineage(note, err);
    BOOST_CHECK_EQUAL(result.code, "NOTED");
    BOOST_CHECK(!result.authority);
    BOOST_CHECK(!result.published);
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_SUITE_END()
