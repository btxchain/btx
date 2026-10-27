// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_scriptmesh/scriptmesh.h>
#include <pqkey.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <vector>

BOOST_FIXTURE_TEST_SUITE(swarm_scriptmesh_admit_tests, BasicTestingSetup)

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

BOOST_AUTO_TEST_CASE(short_hash_is_preimage_and_stores_nothing)
{
    modelnet::SwarmScriptMesh mesh;
    const std::vector<unsigned char> short_hash(31, 0x21);
    BOOST_REQUIRE(!mesh.AddHop(Key(0x11), short_hash, 100));
    BOOST_REQUIRE_EQUAL(mesh.code(), "PREIMAGE");
    BOOST_REQUIRE_EQUAL(mesh.hop_count(), 0U);
    BOOST_REQUIRE(!mesh.scripts_ok());
    BOOST_REQUIRE(!mesh.qualified());
    BOOST_REQUIRE(!mesh.secp_penalty());
    BOOST_REQUIRE_EQUAL(mesh.bytes_moved(), 0);
    BOOST_REQUIRE(!mesh.broadcast());
}

BOOST_AUTO_TEST_CASE(short_key_is_key_and_stores_nothing)
{
    modelnet::SwarmScriptMesh mesh;
    const std::vector<unsigned char> short_key(MLDSA44_PUBKEY_SIZE - 1, 0x11);
    BOOST_REQUIRE(!mesh.AddHop(short_key, Hash32(0x21), 100));
    BOOST_REQUIRE_EQUAL(mesh.code(), "KEY");
    BOOST_REQUIRE_EQUAL(mesh.hop_count(), 0U);
    BOOST_REQUIRE(mesh.claim_leaves().empty());
}

BOOST_AUTO_TEST_CASE(empty_claimant_is_key)
{
    modelnet::SwarmScriptMesh mesh;
    BOOST_REQUIRE(!mesh.AddHop({}, Hash32(0x21), 100));
    BOOST_REQUIRE_EQUAL(mesh.code(), "KEY");
    BOOST_REQUIRE_EQUAL(mesh.hop_count(), 0U);
}

BOOST_AUTO_TEST_CASE(fewer_fields_are_preimage)
{
    modelnet::SwarmScriptMesh mesh;
    BOOST_REQUIRE(!mesh.AddHop());
    BOOST_REQUIRE_EQUAL(mesh.code(), "PREIMAGE");
    BOOST_REQUIRE(!mesh.AddHop(Key(0x11)));
    BOOST_REQUIRE_EQUAL(mesh.code(), "PREIMAGE");
    BOOST_REQUIRE(!mesh.AddHop(Key(0x11), Hash32(0x21)));
    BOOST_REQUIRE_EQUAL(mesh.code(), "PREIMAGE");
    BOOST_REQUIRE_EQUAL(mesh.hop_count(), 0U);
    BOOST_REQUIRE(!mesh.broadcast());
    BOOST_REQUIRE_EQUAL(mesh.bytes_moved(), 0);
}

BOOST_AUTO_TEST_CASE(expiry_rise_under_160_stores_nothing)
{
    modelnet::SwarmScriptMesh mesh;
    BOOST_REQUIRE(mesh.AddHop(Key(0x11), Hash32(0x21), 100));
    BOOST_REQUIRE_EQUAL(mesh.hop_count(), 1U);

    BOOST_REQUIRE(!mesh.AddHop(Key(0x12), Hash32(0x22), 259));
    BOOST_REQUIRE_EQUAL(mesh.code(), "TIMEOUT");
    BOOST_REQUIRE_EQUAL(mesh.hop_count(), 1U);
    BOOST_REQUIRE(mesh.hops()[0].claimant == Key(0x11));
    BOOST_REQUIRE_EQUAL(mesh.hops()[0].expiry, 100);

    BOOST_REQUIRE(mesh.AddHop(Key(0x12), Hash32(0x22), 260));
    BOOST_REQUIRE_EQUAL(mesh.hop_count(), 2U);
    BOOST_REQUIRE(mesh.code().empty());
    BOOST_REQUIRE(!mesh.qualified());
    BOOST_REQUIRE(!mesh.secp_penalty());
}

BOOST_AUTO_TEST_SUITE_END()
