// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_originnote.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_originnote_tests, BasicTestingSetup)

static modelnet::SwarmImportOrigin NotedOrigin()
{
    modelnet::SwarmImportOrigin origin;
    origin.url = "https://example.invalid/model";
    origin.import_origin = false;
    origin.want_lineage = false;
    return origin;
}

BOOST_AUTO_TEST_CASE(empty_url_is_origin)
{
    modelnet::SwarmImportOrigin origin = NotedOrigin();
    origin.url.clear();
    std::string err = "prior";
    const modelnet::SwarmImportOriginResult result = modelnet::SwarmNoteImportOrigin(origin, err);
    BOOST_CHECK(!result.lineage_authority);
    BOOST_CHECK_EQUAL(result.code, "ORIGIN");
    BOOST_CHECK_EQUAL(err, "ORIGIN");
}

BOOST_AUTO_TEST_CASE(empty_url_wins_over_want_lineage_and_import_origin)
{
    modelnet::SwarmImportOrigin origin = NotedOrigin();
    origin.url.clear();
    origin.import_origin = true;
    origin.want_lineage = true;
    std::string err = "prior";
    const modelnet::SwarmImportOriginResult result = modelnet::SwarmNoteImportOrigin(origin, err);
    BOOST_CHECK(!result.lineage_authority);
    BOOST_CHECK_EQUAL(result.code, "ORIGIN");
    BOOST_CHECK_EQUAL(err, "ORIGIN");
}

BOOST_AUTO_TEST_CASE(want_lineage_is_not_authority)
{
    modelnet::SwarmImportOrigin origin = NotedOrigin();
    origin.want_lineage = true;
    std::string err = "prior";
    const modelnet::SwarmImportOriginResult result = modelnet::SwarmNoteImportOrigin(origin, err);
    BOOST_CHECK(!result.lineage_authority);
    BOOST_CHECK_EQUAL(result.code, "NOT_AUTHORITY");
    BOOST_CHECK_EQUAL(err, "NOT_AUTHORITY");
}

BOOST_AUTO_TEST_CASE(want_lineage_wins_when_import_origin_is_true)
{
    modelnet::SwarmImportOrigin origin = NotedOrigin();
    origin.import_origin = true;
    origin.want_lineage = true;
    std::string err = "prior";
    const modelnet::SwarmImportOriginResult result = modelnet::SwarmNoteImportOrigin(origin, err);
    BOOST_CHECK(!result.lineage_authority);
    BOOST_CHECK_EQUAL(result.code, "NOT_AUTHORITY");
    BOOST_CHECK_EQUAL(err, "NOT_AUTHORITY");
}

BOOST_AUTO_TEST_CASE(nonempty_url_is_noted)
{
    modelnet::SwarmImportOrigin origin = NotedOrigin();
    std::string err = "prior";
    const modelnet::SwarmImportOriginResult result = modelnet::SwarmNoteImportOrigin(origin, err);
    BOOST_CHECK(!result.lineage_authority);
    BOOST_CHECK_EQUAL(result.code, "NOTED");
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_CASE(import_origin_is_noted_and_is_not_lineage_authority)
{
    modelnet::SwarmImportOrigin origin = NotedOrigin();
    origin.import_origin = true;
    std::string err = "prior";
    const modelnet::SwarmImportOriginResult result = modelnet::SwarmNoteImportOrigin(origin, err);
    BOOST_CHECK(!result.lineage_authority);
    BOOST_CHECK_EQUAL(result.code, "NOTED");
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_SUITE_END()
