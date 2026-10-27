// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notquorum.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_notquorum_tests, BasicTestingSetup)

static modelnet::SwarmNotQuorum NotedNote()
{
    modelnet::SwarmNotQuorum note;
    note.report_id = "report-1";
    note.want_settle = false;
    return note;
}

BOOST_AUTO_TEST_CASE(empty_report_id_is_report)
{
    modelnet::SwarmNotQuorum note = NotedNote();
    note.report_id.clear();
    std::string err = "prior";
    const modelnet::SwarmNotQuorumResult result = modelnet::SwarmNoteNotQuorum(note, err);
    BOOST_CHECK(!result.settled);
    BOOST_CHECK_EQUAL(result.code, "REPORT");
    BOOST_CHECK_EQUAL(err, "REPORT");
}

BOOST_AUTO_TEST_CASE(want_settle_is_not_quorum)
{
    modelnet::SwarmNotQuorum note = NotedNote();
    note.want_settle = true;
    std::string err = "prior";
    const modelnet::SwarmNotQuorumResult result = modelnet::SwarmNoteNotQuorum(note, err);
    BOOST_CHECK(!result.settled);
    BOOST_CHECK_EQUAL(result.code, "NOT_QUORUM");
    BOOST_CHECK_EQUAL(err, "NOT_QUORUM");
}

BOOST_AUTO_TEST_CASE(plain_note_is_noted)
{
    modelnet::SwarmNotQuorum note = NotedNote();
    note.want_settle = false;
    std::string err = "prior";
    const modelnet::SwarmNotQuorumResult result = modelnet::SwarmNoteNotQuorum(note, err);
    BOOST_CHECK(!result.settled);
    BOOST_CHECK_EQUAL(result.code, "NOTED");
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_SUITE_END()
