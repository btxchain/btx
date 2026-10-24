// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notttft.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_notttft_tests, BasicTestingSetup)

static modelnet::SwarmNotTtft NotedNote()
{
    modelnet::SwarmNotTtft note;
    note.node_id = "node-1";
    note.want_publish = false;
    return note;
}

BOOST_AUTO_TEST_CASE(empty_node_id_is_ttft)
{
    modelnet::SwarmNotTtft note = NotedNote();
    note.node_id.clear();
    std::string err = "prior";
    const modelnet::SwarmNotTtftResult result = modelnet::SwarmNoteNotTtft(note, err);
    BOOST_CHECK(!result.published);
    BOOST_CHECK_EQUAL(result.code, "TTFT");
    BOOST_CHECK_EQUAL(err, "TTFT");
}

BOOST_AUTO_TEST_CASE(want_publish_is_unmeasured)
{
    modelnet::SwarmNotTtft note = NotedNote();
    note.want_publish = true;
    std::string err = "prior";
    const modelnet::SwarmNotTtftResult result = modelnet::SwarmNoteNotTtft(note, err);
    BOOST_CHECK(!result.published);
    BOOST_CHECK_EQUAL(result.code, "UNMEASURED");
    BOOST_CHECK_EQUAL(err, "UNMEASURED");
}

BOOST_AUTO_TEST_CASE(plain_note_is_noted)
{
    modelnet::SwarmNotTtft note = NotedNote();
    std::string err = "prior";
    const modelnet::SwarmNotTtftResult result = modelnet::SwarmNoteNotTtft(note, err);
    BOOST_CHECK(!result.published);
    BOOST_CHECK_EQUAL(result.code, "NOTED");
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_SUITE_END()
