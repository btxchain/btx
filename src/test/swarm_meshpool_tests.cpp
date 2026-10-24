// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_meshpool.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_meshpool_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(empty_mesh_or_pool_is_mesh)
{
    std::string err = "prior";
    modelnet::SwarmMeshPools missing_mesh;
    missing_mesh.pool_a = "pool-a";
    missing_mesh.pool_b = "pool-b";
    missing_mesh.want_merge = true;
    const modelnet::SwarmMeshPoolsResult no_mesh = modelnet::SwarmNoteMeshPools(missing_mesh, err);
    BOOST_CHECK(!no_mesh.merged);
    BOOST_CHECK_EQUAL(no_mesh.code, "MESH");
    BOOST_CHECK_EQUAL(err, "MESH");

    modelnet::SwarmMeshPools missing_a;
    missing_a.mesh_id = "mesh-1";
    missing_a.pool_b = "pool-b";
    missing_a.want_merge = true;
    const modelnet::SwarmMeshPoolsResult no_a = modelnet::SwarmNoteMeshPools(missing_a, err);
    BOOST_CHECK(!no_a.merged);
    BOOST_CHECK_EQUAL(no_a.code, "MESH");
    BOOST_CHECK_EQUAL(err, "MESH");

    modelnet::SwarmMeshPools missing_b;
    missing_b.mesh_id = "mesh-1";
    missing_b.pool_a = "pool-a";
    missing_b.want_merge = true;
    const modelnet::SwarmMeshPoolsResult no_b = modelnet::SwarmNoteMeshPools(missing_b, err);
    BOOST_CHECK(!no_b.merged);
    BOOST_CHECK_EQUAL(no_b.code, "MESH");
    BOOST_CHECK_EQUAL(err, "MESH");
}

BOOST_AUTO_TEST_CASE(same_pool_twice_is_same_even_when_merge_is_requested)
{
    std::string err = "prior";
    modelnet::SwarmMeshPools note;
    note.mesh_id = "mesh-1";
    note.pool_a = "pool-a";
    note.pool_b = "pool-a";
    note.want_merge = true;
    const modelnet::SwarmMeshPoolsResult merged_ask = modelnet::SwarmNoteMeshPools(note, err);
    BOOST_CHECK(!merged_ask.merged);
    BOOST_CHECK_EQUAL(merged_ask.code, "SAME");
    BOOST_CHECK_EQUAL(err, "SAME");

    modelnet::SwarmMeshPools held;
    held.mesh_id = "mesh-1";
    held.pool_a = "pool-a";
    held.pool_b = "pool-a";
    held.want_merge = false;
    const modelnet::SwarmMeshPoolsResult same = modelnet::SwarmNoteMeshPools(held, err);
    BOOST_CHECK(!same.merged);
    BOOST_CHECK_EQUAL(same.code, "SAME");
    BOOST_CHECK_EQUAL(err, "SAME");
}

BOOST_AUTO_TEST_CASE(want_merge_keeps_pools_separate)
{
    std::string err = "prior";
    modelnet::SwarmMeshPools note;
    note.mesh_id = "mesh-1";
    note.pool_a = "pool-a";
    note.pool_b = "pool-b";
    note.want_merge = true;
    const modelnet::SwarmMeshPoolsResult result = modelnet::SwarmNoteMeshPools(note, err);
    BOOST_CHECK(!result.merged);
    BOOST_CHECK_EQUAL(result.code, "SEPARATE");
    BOOST_CHECK_EQUAL(err, "SEPARATE");
}

BOOST_AUTO_TEST_CASE(noted_clears_err_and_does_not_merge)
{
    std::string err = "prior";
    modelnet::SwarmMeshPools note;
    note.mesh_id = "mesh-1";
    note.pool_a = "pool-a";
    note.pool_b = "pool-b";
    note.want_merge = false;
    const modelnet::SwarmMeshPoolsResult result = modelnet::SwarmNoteMeshPools(note, err);
    BOOST_CHECK(!result.merged);
    BOOST_CHECK_EQUAL(result.code, "NOTED");
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_SUITE_END()
