// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnodomain.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_notnodomain_tests, BasicTestingSetup)

static modelnet::SwarmNotNoDomain NotedNote()
{
    modelnet::SwarmNotNoDomain note;
    note.report_id = "report-1";
    note.same_domain = false;
    note.want_settle = false;
    return note;
}

BOOST_AUTO_TEST_CASE(empty_report_id_is_report)
{
    modelnet::SwarmNotNoDomain note = NotedNote();
    note.report_id.clear();
    note.same_domain = true;
    note.want_settle = true;
    std::string err = "prior";
    const modelnet::SwarmNotNoDomainResult result = modelnet::SwarmNoteNotNoDomain(note, err);
    BOOST_CHECK(!result.settled);
    BOOST_CHECK(!result.bytes_moved);
    BOOST_CHECK_EQUAL(result.code, "REPORT");
    BOOST_CHECK_EQUAL(err, "REPORT");
}

BOOST_AUTO_TEST_CASE(same_domain_is_same_domain)
{
    modelnet::SwarmNotNoDomain note = NotedNote();
    note.same_domain = true;
    note.want_settle = false;
    std::string err = "prior";
    const modelnet::SwarmNotNoDomainResult result = modelnet::SwarmNoteNotNoDomain(note, err);
    BOOST_CHECK(!result.settled);
    BOOST_CHECK(!result.bytes_moved);
    BOOST_CHECK_EQUAL(result.code, "SAME_DOMAIN");
    BOOST_CHECK_EQUAL(err, "SAME_DOMAIN");
}

BOOST_AUTO_TEST_CASE(want_settle_distinct_domains_is_held)
{
    modelnet::SwarmNotNoDomain note = NotedNote();
    note.same_domain = false;
    note.want_settle = true;
    std::string err = "prior";
    const modelnet::SwarmNotNoDomainResult result = modelnet::SwarmNoteNotNoDomain(note, err);
    BOOST_CHECK(!result.settled);
    BOOST_CHECK(!result.bytes_moved);
    BOOST_CHECK_EQUAL(result.code, "HELD");
    BOOST_CHECK_EQUAL(err, "HELD");
}

BOOST_AUTO_TEST_CASE(plain_distinct_domains_is_noted)
{
    modelnet::SwarmNotNoDomain note = NotedNote();
    note.same_domain = false;
    note.want_settle = false;
    std::string err = "prior";
    const modelnet::SwarmNotNoDomainResult result = modelnet::SwarmNoteNotNoDomain(note, err);
    BOOST_CHECK(!result.settled);
    BOOST_CHECK(!result.bytes_moved);
    BOOST_CHECK_EQUAL(result.code, "NOTED");
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_SUITE_END()
