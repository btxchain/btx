// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notmesh.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_notmesh_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(empty_mesh_id)
{
    modelnet::SwarmNotMesh note;
    std::string err = "prior";
    const modelnet::SwarmNotMeshResult result = modelnet::SwarmNoteNotMesh(note, err);
    BOOST_CHECK_EQUAL(result.code, "MESH");
    BOOST_CHECK(!result.opened);
    BOOST_CHECK(!result.broadcast);
    BOOST_CHECK_EQUAL(err, "MESH");
}

BOOST_AUTO_TEST_CASE(mesh_count_2)
{
    modelnet::SwarmNotMesh note;
    note.mesh_id = "mesh-1";
    note.mesh_count = 2;
    note.want_open = false;
    std::string err = "prior";
    const modelnet::SwarmNotMeshResult result = modelnet::SwarmNoteNotMesh(note, err);
    BOOST_CHECK_EQUAL(result.code, "ONE_MESH");
    BOOST_CHECK(!result.opened);
    BOOST_CHECK(!result.broadcast);
    BOOST_CHECK_EQUAL(err, "ONE_MESH");
}

BOOST_AUTO_TEST_CASE(want_open_mesh_count_1)
{
    modelnet::SwarmNotMesh note;
    note.mesh_id = "mesh-1";
    note.mesh_count = 1;
    note.want_open = true;
    std::string err = "prior";
    const modelnet::SwarmNotMeshResult result = modelnet::SwarmNoteNotMesh(note, err);
    BOOST_CHECK_EQUAL(result.code, "ONE_MESH");
    BOOST_CHECK(!result.opened);
    BOOST_CHECK(!result.broadcast);
    BOOST_CHECK_EQUAL(err, "ONE_MESH");
}

BOOST_AUTO_TEST_CASE(plain_note_mesh_count_1)
{
    modelnet::SwarmNotMesh note;
    note.mesh_id = "mesh-1";
    note.mesh_count = 1;
    note.want_open = false;
    std::string err = "prior";
    const modelnet::SwarmNotMeshResult result = modelnet::SwarmNoteNotMesh(note, err);
    BOOST_CHECK_EQUAL(result.code, "NOTED");
    BOOST_CHECK(!result.opened);
    BOOST_CHECK(!result.broadcast);
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_SUITE_END()
