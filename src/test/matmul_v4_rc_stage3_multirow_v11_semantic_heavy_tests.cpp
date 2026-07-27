// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <boost/test/unit_test.hpp>

#include <matmul/matmul_v4_rc_stage3_multirow_v11_semantic_heavy.h>

#include <cstdlib>
#include <set>

namespace {

namespace heavy =
    matmul::v4::rc::multirow_v11_semantic_heavy;
namespace rc = matmul::v4::rc;
namespace gf = matmul::v4::rc::gkr_field;

uint256 Seed()
{
    uint256 out;
    for (uint32_t i = 0; i < 32; ++i) {
        out.begin()[i] =
            static_cast<unsigned char>(17U * i + 3U);
    }
    return out;
}

std::array<uint32_t, 8> StreamValue(uint32_t tag)
{
    std::array<uint32_t, 8> out{};
    for (uint32_t i = 0; i < out.size(); ++i) {
        out[i] = 0x51000000U + 0x1000U * tag + i;
    }
    return out;
}

} // namespace

BOOST_AUTO_TEST_SUITE(
    matmul_v4_rc_stage3_multirow_v11_semantic_heavy_tests)

BOOST_AUTO_TEST_CASE(exact_21_route_and_role_inventory)
{
    const auto routes = heavy::CanonicalHeavyRoutesV1();
    const std::array<uint16_t, 21> expected{
        2, 3, 12, 19, 20, 21, 22, 23, 24, 25, 26,
        27, 29, 35, 44, 47, 48, 49, 50, 51, 52};
    std::set<uint16_t> seen;
    for (uint32_t i = 0; i < routes.size(); ++i) {
        BOOST_CHECK_EQUAL(
            static_cast<uint16_t>(routes[i].endpoint),
            expected[i]);
        BOOST_CHECK_EQUAL(
            routes[i].ordinal + 1U,
            static_cast<uint32_t>(
                routes[i].endpoint));
        BOOST_CHECK(
            seen.insert(expected[i]).second);
        BOOST_CHECK(
            rc::RCStage3StreamFamilyForEndpoint(
                routes[i].endpoint) ==
            routes[i].family);
    }
    BOOST_CHECK_EQUAL(seen.size(), 21U);
}

BOOST_AUTO_TEST_CASE(
    missing_duplicate_role_and_child_are_exact_fail_closed_residuals)
{
    const uint256 seed = Seed();
    const auto empty =
        heavy::BuildProductV1({}, {}, seed);
    BOOST_CHECK(empty.exact_inventory);
    BOOST_CHECK_EQUAL(
        empty.residual_endpoint_ids.size(), 21U);
    BOOST_CHECK(!empty.valid);
    BOOST_CHECK(!empty.complete);
    BOOST_CHECK(!empty.production_authority);
    std::string why;
    BOOST_CHECK(
        !heavy::ValidateProductV1(
            empty, {}, {}, seed, &why));

    std::vector<std::array<uint32_t, 8>> roots(4);
    for (uint32_t i = 0; i < roots.size(); ++i) {
        roots[i] = StreamValue(i);
    }
    const auto role =
        rc::BuildRCStage3PureStreamRoleAirFromRoots(
            rc::RCStage3RelationRole::EpisodeTileTree,
            roots, &why);
    BOOST_REQUIRE_MESSAGE(role.ok, why);
    const auto duplicate_role =
        heavy::BuildProductV1(
            {role, role}, {}, seed);
    BOOST_CHECK(!duplicate_role.no_duplicate_roles);
    BOOST_CHECK(!duplicate_role.valid);

    heavy::HeavyChildProofV1 child;
    child.route =
        heavy::CanonicalHeavyRoutesV1()[3];
    const auto duplicate_child =
        heavy::BuildProductV1(
            {role}, {child, child}, seed);
    BOOST_CHECK(
        !duplicate_child.no_duplicate_children);
    BOOST_CHECK(!duplicate_child.valid);
}

BOOST_AUTO_TEST_CASE(
    wrong_role_ordinal_reorder_root_and_x_plus_p_reject_before_fri)
{
    const auto routes = heavy::CanonicalHeavyRoutesV1();
    const auto route = routes[3]; // EpisodeTileTreeStream.
    const uint256 seed = Seed();
    const auto manifest =
        rc::BuildRCStage3StreamEndpointCanonicalManifest(
            route.family, StreamValue(1), 0, 0);
    std::string why;
    std::array<uint32_t, 8> root{};
    BOOST_REQUIRE(
        rc::RCStage3StreamEndpointCommittedRoot(
            route.family, manifest, root, &why));
    std::vector<std::array<uint32_t, 8>> roots(4);
    roots[0] = root;
    roots[1] = StreamValue(2);
    roots[2] = StreamValue(3);
    roots[3] = StreamValue(4);
    auto role =
        rc::BuildRCStage3PureStreamRoleAirFromRoots(
            route.role, roots, &why);
    BOOST_REQUIRE_MESSAGE(role.ok, why);

    heavy::HeavyChildProofV1 proof;
    proof.route = route;
    proof.manifest = manifest;
    proof.committed_root = root;
    proof.quotient_division_exact = true;

    auto wrong_role = proof;
    wrong_role.route.role =
        rc::RCStage3RelationRole::EpisodeDigest;
    BOOST_CHECK(
        !heavy::VerifyHeavyChildV1(
            role, wrong_role, seed, &why));

    auto wrong_ordinal = proof;
    ++wrong_ordinal.route.ordinal;
    BOOST_CHECK(
        !heavy::VerifyHeavyChildV1(
            role, wrong_ordinal, seed, &why));

    auto wrong_endpoint = proof;
    wrong_endpoint.route.endpoint =
        routes[4].endpoint;
    BOOST_CHECK(
        !heavy::VerifyHeavyChildV1(
            role, wrong_endpoint, seed, &why));

    auto substituted = role;
    substituted.endpoint_committed_roots[0][0] =
        gf::Add(
            substituted.endpoint_committed_roots[0][0],
            gf::FromU64(1));
    BOOST_CHECK(
        !heavy::VerifyHeavyChildV1(
            substituted, proof, seed, &why));

    auto alias = role;
    alias.endpoint_committed_roots[0][0] += gf::kP;
    BOOST_CHECK(
        !heavy::VerifyHeavyChildV1(
            alias, proof, seed, &why));

    auto packed_alias = proof;
    for (uint32_t byte = 0; byte < 8; ++byte) {
        packed_alias.r0_root.data()[byte] =
            static_cast<unsigned char>(
                (gf::kP >> (8U * byte)) & 0xffU);
    }
    // A packed Poseidon digest lane equal to p is noncanonical.  This is the
    // durable-codec form of the same x+p attack and is rejected before FRI.
    BOOST_CHECK(
        !heavy::VerifyHeavyChildV1(
            role, packed_alias, seed, &why));
}

BOOST_AUTO_TEST_CASE(
    simultaneous_claim_expected_mutation_cannot_change_role_owned_root)
{
    const auto route =
        heavy::CanonicalHeavyRoutesV1()[3];
    const uint256 seed = Seed();
    auto manifest =
        rc::BuildRCStage3StreamEndpointCanonicalManifest(
            route.family, StreamValue(7), 0, 0);
    std::string why;
    std::array<uint32_t, 8> old_root{};
    BOOST_REQUIRE(
        rc::RCStage3StreamEndpointCommittedRoot(
            route.family, manifest, old_root, &why));
    std::vector<std::array<uint32_t, 8>> roots(4);
    roots[0] = old_root;
    roots[1] = StreamValue(8);
    roots[2] = StreamValue(9);
    roots[3] = StreamValue(10);
    const auto role =
        rc::BuildRCStage3PureStreamRoleAirFromRoots(
            route.role, roots, &why);
    BOOST_REQUIRE_MESSAGE(role.ok, why);

    ++manifest.stream_value[0];
    std::array<uint32_t, 8> new_root{};
    BOOST_REQUIRE(
        rc::RCStage3StreamEndpointCommittedRoot(
            route.family, manifest, new_root, &why));
    BOOST_CHECK(new_root != old_root);
    heavy::HeavyChildProofV1 forged;
    forged.route = route;
    forged.manifest = manifest;
    forged.committed_root = new_root;
    forged.quotient_division_exact = true;
    // Even if an attacker changes the manifest and both locally repeated
    // root claims, the independently rebuilt role AIR still owns old_root.
    BOOST_CHECK(
        !heavy::VerifyHeavyChildV1(
            role, forged, seed, &why));
}

BOOST_AUTO_TEST_CASE(
    optional_real_sha_child_q192_proof_roundtrip_and_tampers)
{
    if (std::getenv(
            "BTX_RUN_STAGE3_V11_SEMANTIC_HEAVY_PROOF") ==
        nullptr) {
        BOOST_TEST_MESSAGE(
            "set BTX_RUN_STAGE3_V11_SEMANTIC_HEAVY_PROOF=1 "
            "for the real SHA child Q192 Split-RAP proof");
        return;
    }
    const auto route =
        heavy::CanonicalHeavyRoutesV1()[3];
    const uint256 seed = Seed();
    const auto manifest =
        rc::BuildRCStage3StreamEndpointCanonicalManifest(
            route.family, StreamValue(11), 0, 0);
    std::string why;
    std::array<uint32_t, 8> root{};
    BOOST_REQUIRE(
        rc::RCStage3StreamEndpointCommittedRoot(
            route.family, manifest, root, &why));
    std::vector<std::array<uint32_t, 8>> roots(4);
    roots[0] = root;
    roots[1] = StreamValue(12);
    roots[2] = StreamValue(13);
    roots[3] = StreamValue(14);
    const auto role =
        rc::BuildRCStage3PureStreamRoleAirFromRoots(
            route.role, roots, &why);
    BOOST_REQUIRE_MESSAGE(role.ok, why);
    const auto proof =
        heavy::ProveHeavyChildV1(
            role, route.endpoint,
            manifest, seed, &why);
    BOOST_REQUIRE_MESSAGE(
        proof.native_verifier_accepted, why);
    BOOST_CHECK(proof.quotient_division_exact);
    BOOST_CHECK(!proof.r0_root.IsNull());
    BOOST_CHECK(!proof.proof_commitment.IsNull());
    BOOST_CHECK_GT(proof.proof_bytes, 0U);
    BOOST_CHECK(
        heavy::VerifyHeavyChildV1(
            role, proof, seed, &why));
    BOOST_TEST_MESSAGE(
        "semantic-heavy endpoint="
        << static_cast<uint16_t>(route.endpoint)
        << " rows=" << proof.child_rows
        << " columns=" << proof.child_columns
        << " compressions="
        << proof.semantic_compressions
        << " proof_bytes=" << proof.proof_bytes);

    const auto partial =
        heavy::BuildProductV1(
            {role}, {proof}, seed);
    BOOST_CHECK_EQUAL(partial.verified_children, 1U);
    BOOST_CHECK_EQUAL(
        partial.residual_endpoint_ids.size(), 20U);
    BOOST_CHECK(!partial.valid);
    BOOST_CHECK(!partial.complete);
    BOOST_CHECK(!partial.production_authority);

    auto root_tamper = proof;
    root_tamper.r0_root.begin()[0] ^= 1U;
    BOOST_CHECK(
        !heavy::VerifyHeavyChildV1(
            role, root_tamper, seed, &why));

    auto codec_tamper = proof;
    codec_tamper.proof_commitment.begin()[0] ^= 1U;
    BOOST_CHECK(
        !heavy::VerifyHeavyChildV1(
            role, codec_tamper, seed, &why));

    auto proof_tamper = proof;
    BOOST_REQUIRE(
        !proof_tamper.split_rap.batch.groups.empty());
    proof_tamper.split_rap.batch.groups[0].
        row_commit.root[0] =
        gf::Add(
            proof_tamper.split_rap.batch.groups[0].
                row_commit.root[0],
            gf::FromU64(1));
    BOOST_CHECK(
        !heavy::VerifyHeavyChildV1(
            role, proof_tamper, seed, &why));
}

BOOST_AUTO_TEST_SUITE_END()
