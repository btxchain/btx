// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnodomain2.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_notnodomain2_tests, BasicTestingSetup)

static modelnet::SwarmNotNoDomain2 NotedNote()
{
    modelnet::SwarmNotNoDomain2 note;
    note.quorum_id = "quorum-1";
    note.distinct_evaluators = true;
    note.distinct_domains = true;
    note.want_settle = false;
    return note;
}

BOOST_AUTO_TEST_CASE(empty_quorum_id_is_quorum)
{
    modelnet::SwarmNotNoDomain2 note = NotedNote();
    note.quorum_id.clear();
    note.distinct_evaluators = false;
    note.distinct_domains = false;
    note.want_settle = true;
    std::string err = "prior";
    const modelnet::SwarmNotNoDomain2Result result = modelnet::SwarmNoteNotNoDomain2(note, err);
    BOOST_CHECK(!result.settled);
    BOOST_CHECK(!result.bytes_moved);
    BOOST_CHECK_EQUAL(result.code, "QUORUM");
    BOOST_CHECK_EQUAL(err, "QUORUM");
}

BOOST_AUTO_TEST_CASE(same_domain_is_held)
{
    modelnet::SwarmNotNoDomain2 note = NotedNote();
    note.distinct_evaluators = true;
    note.distinct_domains = false;
    note.want_settle = false;
    std::string err = "prior";
    const modelnet::SwarmNotNoDomain2Result result = modelnet::SwarmNoteNotNoDomain2(note, err);
    BOOST_CHECK(!result.settled);
    BOOST_CHECK(!result.bytes_moved);
    BOOST_CHECK_EQUAL(result.code, "HELD");
    BOOST_CHECK_EQUAL(err, "HELD");
}

BOOST_AUTO_TEST_CASE(want_settle_both_distinct_is_held)
{
    modelnet::SwarmNotNoDomain2 note = NotedNote();
    note.distinct_evaluators = true;
    note.distinct_domains = true;
    note.want_settle = true;
    std::string err = "prior";
    const modelnet::SwarmNotNoDomain2Result result = modelnet::SwarmNoteNotNoDomain2(note, err);
    BOOST_CHECK(!result.settled);
    BOOST_CHECK(!result.bytes_moved);
    BOOST_CHECK_EQUAL(result.code, "HELD");
    BOOST_CHECK_EQUAL(err, "HELD");
}

BOOST_AUTO_TEST_CASE(quiet_both_distinct_is_noted)
{
    modelnet::SwarmNotNoDomain2 note = NotedNote();
    note.distinct_evaluators = true;
    note.distinct_domains = true;
    note.want_settle = false;
    std::string err = "prior";
    const modelnet::SwarmNotNoDomain2Result result = modelnet::SwarmNoteNotNoDomain2(note, err);
    BOOST_CHECK(!result.settled);
    BOOST_CHECK(!result.bytes_moved);
    BOOST_CHECK_EQUAL(result.code, "NOTED");
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_SUITE_END()
