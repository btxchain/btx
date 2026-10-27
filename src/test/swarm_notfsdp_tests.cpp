// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notfsdp.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_notfsdp_tests, BasicTestingSetup)

static modelnet::SwarmNotFsdp NotedNote()
{
    modelnet::SwarmNotFsdp note;
    note.node_id = "node-1";
    note.want_fsdp = false;
    return note;
}

BOOST_AUTO_TEST_CASE(empty_node_id_is_train)
{
    modelnet::SwarmNotFsdp note = NotedNote();
    note.node_id.clear();
    std::string err = "prior";
    const modelnet::SwarmNotFsdpResult result = modelnet::SwarmNoteNotFsdp(note, err);
    BOOST_CHECK(!result.distributed);
    BOOST_CHECK_EQUAL(result.code, "TRAIN");
    BOOST_CHECK_EQUAL(err, "TRAIN");
}

BOOST_AUTO_TEST_CASE(want_fsdp_is_not_distributed)
{
    modelnet::SwarmNotFsdp note = NotedNote();
    note.want_fsdp = true;
    std::string err = "prior";
    const modelnet::SwarmNotFsdpResult result = modelnet::SwarmNoteNotFsdp(note, err);
    BOOST_CHECK(!result.distributed);
    BOOST_CHECK_EQUAL(result.code, "NOT_DISTRIBUTED");
    BOOST_CHECK_EQUAL(err, "NOT_DISTRIBUTED");
}

BOOST_AUTO_TEST_CASE(plain_note_is_noted)
{
    modelnet::SwarmNotFsdp note = NotedNote();
    std::string err = "prior";
    const modelnet::SwarmNotFsdpResult result = modelnet::SwarmNoteNotFsdp(note, err);
    BOOST_CHECK(!result.distributed);
    BOOST_CHECK_EQUAL(result.code, "NOTED");
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_SUITE_END()
