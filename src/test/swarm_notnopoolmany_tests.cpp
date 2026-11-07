// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnopoolmany.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_notnopoolmany_tests, BasicTestingSetup)

static modelnet::SwarmNotNoPoolMany NotedNote()
{
    modelnet::SwarmNotNoPoolMany note;
    note.mesh_id = "mesh-1";
    note.want_split = false;
    return note;
}

BOOST_AUTO_TEST_CASE(empty_mesh_id_is_mesh)
{
    modelnet::SwarmNotNoPoolMany note = NotedNote();
    note.mesh_id.clear();
    note.want_split = true;
    std::string err = "prior";
    const modelnet::SwarmNotNoPoolManyResult result = modelnet::SwarmNoteNotNoPoolMany(note, err);
    BOOST_CHECK(!result.split);
    BOOST_CHECK_EQUAL(result.meshes, 0);
    BOOST_CHECK_EQUAL(result.code, "MESH");
    BOOST_CHECK_EQUAL(err, "MESH");
}

BOOST_AUTO_TEST_CASE(want_split_is_one)
{
    modelnet::SwarmNotNoPoolMany note = NotedNote();
    note.want_split = true;
    std::string err = "prior";
    const modelnet::SwarmNotNoPoolManyResult result = modelnet::SwarmNoteNotNoPoolMany(note, err);
    BOOST_CHECK(!result.split);
    BOOST_CHECK_EQUAL(result.meshes, 0);
    BOOST_CHECK_EQUAL(result.code, "ONE");
    BOOST_CHECK_EQUAL(err, "ONE");
}

BOOST_AUTO_TEST_CASE(plain_note_is_noted)
{
    modelnet::SwarmNotNoPoolMany note = NotedNote();
    note.want_split = false;
    std::string err = "prior";
    const modelnet::SwarmNotNoPoolManyResult result = modelnet::SwarmNoteNotNoPoolMany(note, err);
    BOOST_CHECK(!result.split);
    BOOST_CHECK_EQUAL(result.meshes, 0);
    BOOST_CHECK_EQUAL(result.code, "NOTED");
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_SUITE_END()
