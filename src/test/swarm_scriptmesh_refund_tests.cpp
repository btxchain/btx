// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_scriptmesh/scriptmesh.h>
#include <pqkey.h>
#include <script/pqm.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <vector>

BOOST_FIXTURE_TEST_SUITE(swarm_scriptmesh_refund_tests, BasicTestingSetup)

namespace {

std::vector<unsigned char> Key(unsigned char fill)
{
    return std::vector<unsigned char>(MLDSA44_PUBKEY_SIZE, fill);
}

std::vector<unsigned char> Hash32(unsigned char fill)
{
    return std::vector<unsigned char>(32, fill);
}

} // namespace

BOOST_AUTO_TEST_CASE(refund_without_hops_stores_nothing)
{
    modelnet::SwarmScriptMesh mesh;
    BOOST_REQUIRE(!mesh.RefundLeaf());
    BOOST_REQUIRE_EQUAL(mesh.code(), "HOPS");
    BOOST_REQUIRE(mesh.refund_leaf().empty());
    BOOST_REQUIRE(!mesh.broadcast());
    BOOST_REQUIRE_EQUAL(mesh.bytes_moved(), 0);
    BOOST_REQUIRE(!mesh.qualified());
    BOOST_REQUIRE(!mesh.secp_penalty());
}

BOOST_AUTO_TEST_CASE(refund_leaf_parses_for_the_last_hop_and_does_not_broadcast)
{
    modelnet::SwarmScriptMesh mesh;
    const std::vector<unsigned char> key_a = Key(0x11);
    const std::vector<unsigned char> key_b = Key(0x22);
    const std::vector<unsigned char> hash_a = Hash32(0x31);
    const std::vector<unsigned char> hash_b = Hash32(0x32);
    BOOST_REQUIRE(key_b.size() == MLDSA44_PUBKEY_SIZE);
    BOOST_REQUIRE_EQUAL(hash_b.size(), 32U);

    BOOST_REQUIRE(mesh.AddHop(key_a, hash_a, 100));
    BOOST_REQUIRE(mesh.AddHop(key_b, hash_b, 260));
    BOOST_REQUIRE(mesh.Build());
    BOOST_REQUIRE(mesh.scripts_ok());
    BOOST_REQUIRE_EQUAL(mesh.claim_leaves().size(), 2U);

    BOOST_REQUIRE(mesh.RefundLeaf());
    BOOST_REQUIRE(!mesh.refund_leaf().empty());
    BOOST_REQUIRE_EQUAL(mesh.code(), "UNQUALIFIED");
    BOOST_REQUIRE(!mesh.qualified());
    BOOST_REQUIRE(!mesh.secp_penalty());
    BOOST_REQUIRE(!mesh.broadcast());
    BOOST_REQUIRE_EQUAL(mesh.bytes_moved(), 0);
    BOOST_REQUIRE(mesh.scripts_ok());
    BOOST_REQUIRE_EQUAL(mesh.claim_leaves().size(), 2U);

    int64_t locktime{0};
    PQAlgorithm algo{PQAlgorithm::ML_DSA_44};
    std::vector<unsigned char> parsed_key;
    BOOST_REQUIRE(ParseP2MRRefundLeaf(mesh.refund_leaf(), locktime, algo, parsed_key));
    BOOST_REQUIRE_EQUAL(locktime, 260);
    BOOST_REQUIRE(algo == PQAlgorithm::ML_DSA_44);
    BOOST_REQUIRE(parsed_key == key_b);

    const std::vector<unsigned char> first = mesh.refund_leaf();
    BOOST_REQUIRE(mesh.RefundLeaf());
    BOOST_REQUIRE(mesh.refund_leaf() == first);
    BOOST_REQUIRE(!mesh.broadcast());
    BOOST_REQUIRE_EQUAL(mesh.bytes_moved(), 0);
    BOOST_REQUIRE(!mesh.qualified());
}

BOOST_AUTO_TEST_SUITE_END()
