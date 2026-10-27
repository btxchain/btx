// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnopqmesh.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <cstdint>
#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_notnopqmesh_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(empty_mesh_id_is_mesh)
{
    std::string err = "prior";
    modelnet::SwarmNotNoPqMesh note;
    note.mesh_count = 2;
    note.want_second = true;
    const modelnet::SwarmNotNoPqMeshResult result = modelnet::SwarmNoteNotNoPqMesh(note, err);
    BOOST_CHECK(!result.opened);
    BOOST_CHECK_EQUAL(result.meshes, 0);
    BOOST_CHECK_EQUAL(result.code, "MESH");
    BOOST_CHECK_EQUAL(err, "MESH");
}

BOOST_AUTO_TEST_CASE(mesh_count_not_one_is_one_mesh)
{
    std::string err = "prior";
    modelnet::SwarmNotNoPqMesh note;
    note.mesh_id = "pq-mesh";
    note.mesh_count = 2;
    note.want_second = false;
    const modelnet::SwarmNotNoPqMeshResult result = modelnet::SwarmNoteNotNoPqMesh(note, err);
    BOOST_CHECK(!result.opened);
    BOOST_CHECK_EQUAL(result.meshes, 0);
    BOOST_CHECK_EQUAL(result.code, "ONE_MESH");
    BOOST_CHECK_EQUAL(err, "ONE_MESH");
}

BOOST_AUTO_TEST_CASE(want_second_is_one_mesh)
{
    std::string err = "prior";
    modelnet::SwarmNotNoPqMesh note;
    note.mesh_id = "pq-mesh";
    note.mesh_count = 1;
    note.want_second = true;
    const modelnet::SwarmNotNoPqMeshResult result = modelnet::SwarmNoteNotNoPqMesh(note, err);
    BOOST_CHECK(!result.opened);
    BOOST_CHECK_EQUAL(result.meshes, 0);
    BOOST_CHECK_EQUAL(result.code, "ONE_MESH");
    BOOST_CHECK_EQUAL(err, "ONE_MESH");
}

BOOST_AUTO_TEST_CASE(one_mesh_is_noted)
{
    std::string err = "prior";
    modelnet::SwarmNotNoPqMesh note;
    note.mesh_id = "pq-mesh";
    note.mesh_count = 1;
    note.want_second = false;
    const modelnet::SwarmNotNoPqMeshResult result = modelnet::SwarmNoteNotNoPqMesh(note, err);
    BOOST_CHECK(!result.opened);
    BOOST_CHECK_EQUAL(result.meshes, 0);
    BOOST_CHECK_EQUAL(result.code, "NOTED");
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_SUITE_END()
