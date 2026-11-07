// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnopool.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_notnopool_tests, BasicTestingSetup)

static modelnet::SwarmNotNoPool NotedNote()
{
    modelnet::SwarmNotNoPool note;
    note.pool_id = "pool-1";
    note.want_open_mesh = false;
    return note;
}

BOOST_AUTO_TEST_CASE(empty_pool_id_is_pool)
{
    modelnet::SwarmNotNoPool note = NotedNote();
    note.pool_id.clear();
    note.want_open_mesh = true;
    std::string err = "prior";
    const modelnet::SwarmNotNoPoolResult result = modelnet::SwarmNoteNotNoPool(note, err);
    BOOST_CHECK(!result.opened);
    BOOST_CHECK_EQUAL(result.meshes, 0);
    BOOST_CHECK_EQUAL(result.code, "POOL");
    BOOST_CHECK_EQUAL(err, "POOL");
}

BOOST_AUTO_TEST_CASE(want_open_mesh_is_one_mesh)
{
    modelnet::SwarmNotNoPool note = NotedNote();
    note.want_open_mesh = true;
    std::string err = "prior";
    const modelnet::SwarmNotNoPoolResult result = modelnet::SwarmNoteNotNoPool(note, err);
    BOOST_CHECK(!result.opened);
    BOOST_CHECK_EQUAL(result.meshes, 0);
    BOOST_CHECK_EQUAL(result.code, "ONE_MESH");
    BOOST_CHECK_EQUAL(err, "ONE_MESH");
}

BOOST_AUTO_TEST_CASE(plain_note_is_noted)
{
    modelnet::SwarmNotNoPool note = NotedNote();
    note.want_open_mesh = false;
    std::string err = "prior";
    const modelnet::SwarmNotNoPoolResult result = modelnet::SwarmNoteNotNoPool(note, err);
    BOOST_CHECK(!result.opened);
    BOOST_CHECK_EQUAL(result.meshes, 0);
    BOOST_CHECK_EQUAL(result.code, "NOTED");
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_SUITE_END()
