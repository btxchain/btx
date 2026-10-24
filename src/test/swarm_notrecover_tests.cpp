// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notrecover.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_notrecover_tests, BasicTestingSetup)

static modelnet::SwarmNotRecover NotedNote()
{
    modelnet::SwarmNotRecover note;
    note.node_id = "node-1";
    note.want_continue = false;
    return note;
}

BOOST_AUTO_TEST_CASE(empty_node_id_is_node)
{
    modelnet::SwarmNotRecover note = NotedNote();
    note.node_id.clear();
    std::string err = "prior";
    const modelnet::SwarmNotRecoverResult result = modelnet::SwarmNoteNotRecover(note, err);
    BOOST_CHECK(!result.continued);
    BOOST_CHECK_EQUAL(result.code, "NODE");
    BOOST_CHECK_EQUAL(err, "NODE");
}

BOOST_AUTO_TEST_CASE(want_continue_is_not_continued)
{
    modelnet::SwarmNotRecover note = NotedNote();
    note.want_continue = true;
    std::string err = "prior";
    const modelnet::SwarmNotRecoverResult result = modelnet::SwarmNoteNotRecover(note, err);
    BOOST_CHECK(!result.continued);
    BOOST_CHECK_EQUAL(result.code, "NOT_CONTINUED");
    BOOST_CHECK_EQUAL(err, "NOT_CONTINUED");
}

BOOST_AUTO_TEST_CASE(plain_note_is_noted)
{
    modelnet::SwarmNotRecover note = NotedNote();
    note.want_continue = false;
    std::string err = "prior";
    const modelnet::SwarmNotRecoverResult result = modelnet::SwarmNoteNotRecover(note, err);
    BOOST_CHECK(!result.continued);
    BOOST_CHECK_EQUAL(result.code, "NOTED");
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_SUITE_END()
