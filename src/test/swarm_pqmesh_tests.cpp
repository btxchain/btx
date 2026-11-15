// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_pqmesh.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_pqmesh_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(empty_mesh)
{
    modelnet::SwarmPqMesh mesh;
    mesh.mesh_id.clear();
    mesh.want_add = false;
    std::string err;
    const modelnet::SwarmPqMeshResult result = modelnet::SwarmKeepPaymentMesh(mesh, err);
    BOOST_CHECK_EQUAL(result.code, "MESH");
    BOOST_CHECK_EQUAL(err, "MESH");
    BOOST_CHECK(!result.added);
    BOOST_CHECK_EQUAL(result.meshes, 1);
}

BOOST_AUTO_TEST_CASE(want_add_held)
{
    modelnet::SwarmPqMesh mesh;
    mesh.mesh_id = "mesh-1";
    mesh.want_add = true;
    std::string err;
    const modelnet::SwarmPqMeshResult result = modelnet::SwarmKeepPaymentMesh(mesh, err);
    BOOST_CHECK_EQUAL(result.code, "HELD");
    BOOST_CHECK_EQUAL(err, "HELD");
    BOOST_CHECK(!result.added);
    BOOST_CHECK_EQUAL(result.meshes, 1);
}

BOOST_AUTO_TEST_CASE(noted)
{
    modelnet::SwarmPqMesh mesh;
    mesh.mesh_id = "mesh-2";
    mesh.want_add = false;
    std::string err = "stale";
    const modelnet::SwarmPqMeshResult result = modelnet::SwarmKeepPaymentMesh(mesh, err);
    BOOST_CHECK_EQUAL(result.code, "NOTED");
    BOOST_CHECK(err.empty());
    BOOST_CHECK(!result.added);
    BOOST_CHECK_EQUAL(result.meshes, 1);
}

BOOST_AUTO_TEST_SUITE_END()
