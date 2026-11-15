// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_scriptmesh/scriptmesh.h>
#include <pqkey.h>
#include <script/pqm.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <vector>

BOOST_FIXTURE_TEST_SUITE(swarm_scriptmesh_build_tests, BasicTestingSetup)

namespace {

std::vector<unsigned char> Key(unsigned char fill)
{
    return std::vector<unsigned char>(MLDSA44_PUBKEY_SIZE, fill);
}

std::vector<unsigned char> Hash32(unsigned char fill)
{
    return std::vector<unsigned char>(32, fill);
}

void RequireParsedClaim(const std::vector<unsigned char>& script,
                        const std::vector<unsigned char>& hash,
                        const std::vector<unsigned char>& claimant)
{
    std::vector<unsigned char> parsed_hash;
    std::vector<unsigned char> parsed_key;
    PQAlgorithm algo{PQAlgorithm::ML_DSA_44};
    BOOST_REQUIRE(P2MRClaimLeafPinsPreimageLength(script));
    BOOST_REQUIRE(ParseP2MRHTLCSha256Leaf(script, parsed_hash, algo, parsed_key));
    BOOST_REQUIRE(algo == PQAlgorithm::ML_DSA_44);
    BOOST_REQUIRE(parsed_hash == hash);
    BOOST_REQUIRE(parsed_key == claimant);
}

} // namespace

BOOST_AUTO_TEST_CASE(two_hops_parse_back_and_stay_unqualified)
{
    modelnet::SwarmScriptMesh mesh;
    BOOST_REQUIRE(!mesh.qualified());
    BOOST_REQUIRE(!mesh.secp_penalty());
    BOOST_REQUIRE(!mesh.scripts_ok());
    BOOST_REQUIRE_EQUAL(mesh.bytes_moved(), 0);
    BOOST_REQUIRE(!mesh.broadcast());

    const std::vector<unsigned char> short_hash(31, 0x21);
    BOOST_REQUIRE(!mesh.AddHop(Key(0x11), short_hash, 100));
    BOOST_REQUIRE_EQUAL(mesh.code(), "PREIMAGE");

    const std::vector<unsigned char> short_key(MLDSA44_PUBKEY_SIZE - 1, 0x11);
    BOOST_REQUIRE(!mesh.AddHop(short_key, Hash32(0x21), 100));
    BOOST_REQUIRE_EQUAL(mesh.code(), "KEY");
    BOOST_REQUIRE_EQUAL(mesh.hop_count(), 0U);

    const std::vector<unsigned char> key_a = Key(0x11);
    const std::vector<unsigned char> key_b = Key(0x22);
    const std::vector<unsigned char> hash_a = Hash32(0x31);
    const std::vector<unsigned char> hash_b = Hash32(0x32);
    BOOST_REQUIRE(key_a.size() == MLDSA44_PUBKEY_SIZE);
    BOOST_REQUIRE_EQUAL(hash_a.size(), 32U);

    BOOST_REQUIRE(mesh.AddHop(key_a, hash_a, 100));
    BOOST_REQUIRE(!mesh.AddHop(key_b, hash_b, 259));
    BOOST_REQUIRE_EQUAL(mesh.code(), "TIMEOUT");
    BOOST_REQUIRE_EQUAL(mesh.hop_count(), 1U);

    BOOST_REQUIRE(mesh.AddHop(key_b, hash_b, 260));
    BOOST_REQUIRE_EQUAL(mesh.hop_count(), 2U);
    BOOST_REQUIRE(mesh.Build());
    BOOST_REQUIRE(mesh.scripts_ok());
    BOOST_REQUIRE_EQUAL(mesh.code(), "UNQUALIFIED");
    BOOST_REQUIRE(!mesh.qualified());
    BOOST_REQUIRE(!mesh.secp_penalty());
    BOOST_REQUIRE_EQUAL(mesh.bytes_moved(), 0);
    BOOST_REQUIRE(!mesh.broadcast());
    BOOST_REQUIRE_EQUAL(mesh.claim_leaves().size(), 2U);
    BOOST_REQUIRE(mesh.claim_leaves()[0] != mesh.claim_leaves()[1]);
    RequireParsedClaim(mesh.claim_leaves()[0], hash_a, key_a);
    RequireParsedClaim(mesh.claim_leaves()[1], hash_b, key_b);
}

BOOST_AUTO_TEST_CASE(second_build_of_the_same_hops_is_replay)
{
    modelnet::SwarmScriptMesh mesh;
    BOOST_REQUIRE(mesh.AddHop(Key(0x11), Hash32(0x31), 100));
    BOOST_REQUIRE(mesh.AddHop(Key(0x22), Hash32(0x32), 260));
    BOOST_REQUIRE(mesh.Build());
    const std::vector<std::vector<unsigned char>> first = mesh.claim_leaves();
    BOOST_REQUIRE_EQUAL(first.size(), 2U);

    BOOST_REQUIRE(!mesh.Build());
    BOOST_REQUIRE_EQUAL(mesh.code(), "REPLAY");
    BOOST_REQUIRE(mesh.scripts_ok());
    BOOST_REQUIRE(mesh.claim_leaves() == first);
    BOOST_REQUIRE_EQUAL(mesh.claim_leaves().size(), 2U);
    BOOST_REQUIRE(!mesh.qualified());
    BOOST_REQUIRE(!mesh.secp_penalty());
    BOOST_REQUIRE(!mesh.broadcast());
    BOOST_REQUIRE_EQUAL(mesh.bytes_moved(), 0);
}

BOOST_AUTO_TEST_CASE(one_hop_does_not_build)
{
    modelnet::SwarmScriptMesh mesh;
    BOOST_REQUIRE(!mesh.Build());
    BOOST_REQUIRE_EQUAL(mesh.code(), "HOPS");
    BOOST_REQUIRE(mesh.AddHop(Key(0x11), Hash32(0x31), 100));
    BOOST_REQUIRE(!mesh.Build());
    BOOST_REQUIRE_EQUAL(mesh.code(), "HOPS");
    BOOST_REQUIRE(!mesh.scripts_ok());
    BOOST_REQUIRE(mesh.claim_leaves().empty());
    BOOST_REQUIRE_EQUAL(mesh.hop_count(), 1U);
}

BOOST_AUTO_TEST_CASE(added_hop_rebuilds_without_appending)
{
    modelnet::SwarmScriptMesh mesh;
    const std::vector<unsigned char> key_c = Key(0x33);
    const std::vector<unsigned char> hash_c = Hash32(0x43);
    BOOST_REQUIRE(mesh.AddHop(Key(0x11), Hash32(0x31), 100));
    BOOST_REQUIRE(mesh.AddHop(Key(0x22), Hash32(0x32), 260));
    BOOST_REQUIRE(mesh.Build());
    BOOST_REQUIRE_EQUAL(mesh.claim_leaves().size(), 2U);

    BOOST_REQUIRE(mesh.AddHop(key_c, hash_c, 420));
    BOOST_REQUIRE(!mesh.scripts_ok());
    BOOST_REQUIRE(mesh.claim_leaves().empty());
    BOOST_REQUIRE(mesh.Build());
    BOOST_REQUIRE_EQUAL(mesh.claim_leaves().size(), 3U);
    BOOST_REQUIRE(mesh.scripts_ok());
    BOOST_REQUIRE_EQUAL(mesh.code(), "UNQUALIFIED");
    BOOST_REQUIRE(!mesh.qualified());
    RequireParsedClaim(mesh.claim_leaves()[2], hash_c, key_c);

    const std::vector<std::vector<unsigned char>> built = mesh.claim_leaves();
    BOOST_REQUIRE(!mesh.Build());
    BOOST_REQUIRE_EQUAL(mesh.code(), "REPLAY");
    BOOST_REQUIRE(mesh.claim_leaves() == built);
}

BOOST_AUTO_TEST_SUITE_END()
