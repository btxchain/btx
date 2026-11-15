// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnothreads2.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_notnothreads2_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(empty_node_id_is_node)
{
    modelnet::SwarmNotNoThreads2 note;
    note.requested = 65;
    note.want_raise = true;
    std::string err = "prior";
    const modelnet::SwarmNotNoThreads2Result result = modelnet::SwarmNoteNotNoThreads2(note, err);
    BOOST_CHECK_EQUAL(result.raised, false);
    BOOST_CHECK_EQUAL(result.threads, 0);
    BOOST_CHECK_EQUAL(result.code, "NODE");
    BOOST_CHECK_EQUAL(err, "NODE");
}

BOOST_AUTO_TEST_CASE(requested_65_is_capped)
{
    modelnet::SwarmNotNoThreads2 note;
    note.node_id = "node-1";
    note.requested = 65;
    note.want_raise = false;
    std::string err = "prior";
    const modelnet::SwarmNotNoThreads2Result result = modelnet::SwarmNoteNotNoThreads2(note, err);
    BOOST_CHECK_EQUAL(result.raised, false);
    BOOST_CHECK_EQUAL(result.threads, 0);
    BOOST_CHECK_EQUAL(result.code, "CAPPED");
    BOOST_CHECK_EQUAL(err, "CAPPED");
}

BOOST_AUTO_TEST_CASE(want_raise_requested_1_is_capped)
{
    modelnet::SwarmNotNoThreads2 note;
    note.node_id = "node-1";
    note.requested = 1;
    note.want_raise = true;
    std::string err = "prior";
    const modelnet::SwarmNotNoThreads2Result result = modelnet::SwarmNoteNotNoThreads2(note, err);
    BOOST_CHECK_EQUAL(result.raised, false);
    BOOST_CHECK_EQUAL(result.threads, 0);
    BOOST_CHECK_EQUAL(result.code, "CAPPED");
    BOOST_CHECK_EQUAL(err, "CAPPED");
}

BOOST_AUTO_TEST_CASE(quiet_note_requested_64_is_noted)
{
    modelnet::SwarmNotNoThreads2 note;
    note.node_id = "node-1";
    note.requested = 64;
    note.want_raise = false;
    std::string err = "prior";
    const modelnet::SwarmNotNoThreads2Result result = modelnet::SwarmNoteNotNoThreads2(note, err);
    BOOST_CHECK_EQUAL(result.raised, false);
    BOOST_CHECK_EQUAL(result.threads, 0);
    BOOST_CHECK_EQUAL(result.code, "NOTED");
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_SUITE_END()
