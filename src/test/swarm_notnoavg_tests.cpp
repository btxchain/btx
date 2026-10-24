// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnoavg.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_notnoavg_tests, BasicTestingSetup)

static modelnet::SwarmNotNoAvg NotedNote()
{
    modelnet::SwarmNotNoAvg note;
    note.branch_id = "branch-1";
    note.compatible = true;
    note.want_average = false;
    return note;
}

BOOST_AUTO_TEST_CASE(empty_branch_id_is_branch)
{
    modelnet::SwarmNotNoAvg note = NotedNote();
    note.branch_id.clear();
    std::string err = "prior";
    const modelnet::SwarmNotNoAvgResult result = modelnet::SwarmNoteNotNoAvg(note, err);
    BOOST_CHECK(!result.averaged);
    BOOST_CHECK(!result.bytes_moved);
    BOOST_CHECK_EQUAL(result.code, "BRANCH");
    BOOST_CHECK_EQUAL(err, "BRANCH");
}

BOOST_AUTO_TEST_CASE(incompatible_without_want_average_is_separate)
{
    modelnet::SwarmNotNoAvg note = NotedNote();
    note.compatible = false;
    note.want_average = false;
    std::string err = "prior";
    const modelnet::SwarmNotNoAvgResult result = modelnet::SwarmNoteNotNoAvg(note, err);
    BOOST_CHECK(!result.averaged);
    BOOST_CHECK(!result.bytes_moved);
    BOOST_CHECK_EQUAL(result.code, "SEPARATE");
    BOOST_CHECK_EQUAL(err, "SEPARATE");
}

BOOST_AUTO_TEST_CASE(want_average_with_compatible_is_held)
{
    modelnet::SwarmNotNoAvg note = NotedNote();
    note.compatible = true;
    note.want_average = true;
    std::string err = "prior";
    const modelnet::SwarmNotNoAvgResult result = modelnet::SwarmNoteNotNoAvg(note, err);
    BOOST_CHECK(!result.averaged);
    BOOST_CHECK(!result.bytes_moved);
    BOOST_CHECK_EQUAL(result.code, "HELD");
    BOOST_CHECK_EQUAL(err, "HELD");
}

BOOST_AUTO_TEST_CASE(plain_compatible_note_is_noted)
{
    modelnet::SwarmNotNoAvg note = NotedNote();
    note.compatible = true;
    note.want_average = false;
    std::string err = "prior";
    const modelnet::SwarmNotNoAvgResult result = modelnet::SwarmNoteNotNoAvg(note, err);
    BOOST_CHECK(!result.averaged);
    BOOST_CHECK(!result.bytes_moved);
    BOOST_CHECK_EQUAL(result.code, "NOTED");
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_SUITE_END()
