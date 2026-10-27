// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnocltvfirst2.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_notnocltvfirst2_tests, BasicTestingSetup)

static modelnet::SwarmNotNoCltvFirst2 NotedNote()
{
    modelnet::SwarmNotNoCltvFirst2 note;
    note.edge_id = "edge-1";
    note.first_edge = false;
    note.want_add = false;
    return note;
}

BOOST_AUTO_TEST_CASE(empty)
{
    modelnet::SwarmNotNoCltvFirst2 note = NotedNote();
    note.edge_id.clear();
    note.first_edge = true;
    note.want_add = true;
    std::string err = "prior";
    const modelnet::SwarmNotNoCltvFirst2Result result = modelnet::SwarmNoteNotNoCltvFirst2(note, err);
    BOOST_CHECK(!result.added);
    BOOST_CHECK_EQUAL(result.code, "EDGE");
    BOOST_CHECK_EQUAL(err, "EDGE");
}

BOOST_AUTO_TEST_CASE(first_edge)
{
    modelnet::SwarmNotNoCltvFirst2 note = NotedNote();
    note.first_edge = true;
    note.want_add = false;
    std::string err = "prior";
    const modelnet::SwarmNotNoCltvFirst2Result result = modelnet::SwarmNoteNotNoCltvFirst2(note, err);
    BOOST_CHECK(!result.added);
    BOOST_CHECK_EQUAL(result.code, "NOT_ADDED");
    BOOST_CHECK_EQUAL(err, "NOT_ADDED");
}

BOOST_AUTO_TEST_CASE(want_add)
{
    modelnet::SwarmNotNoCltvFirst2 note = NotedNote();
    note.edge_id = "edge-2";
    note.first_edge = false;
    note.want_add = true;
    std::string err = "prior";
    const modelnet::SwarmNotNoCltvFirst2Result result = modelnet::SwarmNoteNotNoCltvFirst2(note, err);
    BOOST_CHECK(!result.added);
    BOOST_CHECK_EQUAL(result.code, "HELD");
    BOOST_CHECK_EQUAL(err, "HELD");
}

BOOST_AUTO_TEST_CASE(plain_later_edge)
{
    modelnet::SwarmNotNoCltvFirst2 note = NotedNote();
    note.edge_id = "edge-2";
    note.first_edge = false;
    note.want_add = false;
    std::string err = "prior";
    const modelnet::SwarmNotNoCltvFirst2Result result = modelnet::SwarmNoteNotNoCltvFirst2(note, err);
    BOOST_CHECK(!result.added);
    BOOST_CHECK_EQUAL(result.code, "NOTED");
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_SUITE_END()
