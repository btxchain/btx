// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <boost/test/unit_test.hpp>

#include <matmul/matmul_v4_rc_air_recurse.h>
#include <matmul/matmul_v4_rc_stage3_multirow_v11_semantic_exports.h>

#include <algorithm>

namespace {

namespace exports =
    matmul::v4::rc::multirow_v11_semantic_exports;
namespace rc = matmul::v4::rc;
namespace gf = matmul::v4::rc::gkr_field;

const exports::CanonicalExportRouteV1& Route(
    const std::array<
        exports::CanonicalExportRouteV1,
        exports::kEndpointCountV1>& routes,
    rc::RCStage3RelationEndpoint endpoint)
{
    return routes.at(
        static_cast<uint32_t>(endpoint) - 1U);
}

} // namespace

BOOST_AUTO_TEST_SUITE(
    matmul_v4_rc_stage3_multirow_v11_semantic_exports_tests)

BOOST_AUTO_TEST_CASE(
    exact_52_route_inventory_has_no_metadata_only_endpoint)
{
    const auto routes = exports::CanonicalExportRoutesV1();
    uint32_t direct = 0;
    uint32_t vectors = 0;
    uint32_t wired = 0;
    uint32_t streams = 0;
    for (uint32_t i = 0; i < routes.size(); ++i) {
        const auto& route = routes[i];
        BOOST_CHECK_EQUAL(
            static_cast<uint32_t>(route.endpoint),
            i + 1U);
        BOOST_CHECK_EQUAL(route.ordinal, i);
        BOOST_CHECK(
            route.kind !=
            exports::ProducerKindV1::Absent);
        BOOST_CHECK(route.producer_module != nullptr);
        BOOST_CHECK(route.producer_function != nullptr);
        direct +=
            route.kind ==
            exports::ProducerKindV1::DirectRelationCell;
        vectors +=
            route.kind ==
            exports::ProducerKindV1::VectorOpening;
        wired +=
            route.kind ==
            exports::ProducerKindV1::WiredLedger;
        streams +=
            route.kind ==
            exports::ProducerKindV1::StreamChild;
    }
    BOOST_CHECK_EQUAL(direct, 26U);
    BOOST_CHECK_EQUAL(vectors, 0U);
    BOOST_CHECK_EQUAL(wired, 5U);
    BOOST_CHECK_EQUAL(streams, 21U);

    BOOST_CHECK((
        Route(
            routes,
            rc::RCStage3RelationEndpoint::
                EpisodeGemmSignedRange).kind ==
        exports::ProducerKindV1::DirectRelationCell));
    BOOST_CHECK((
        Route(
            routes,
            rc::RCStage3RelationEndpoint::
                EpisodeTileTreeInternalHash).kind ==
        exports::ProducerKindV1::StreamChild));
    BOOST_CHECK((
        Route(
            routes,
            rc::RCStage3RelationEndpoint::
                CoupledDigestValue).kind ==
        exports::ProducerKindV1::StreamChild));
}

BOOST_AUTO_TEST_CASE(
    real_role_air_execution_adds_vector_and_wired_exports)
{
    std::string why;
    const gf::Fp3 copy =
        gf::Fp3::FromFp(gf::FromU64(0x912345U));
    const rc::RCStage3RoleAirProduct role =
        rc::BuildRCStage3EpisodeWiringRoleAir(
            &why, &copy);
    BOOST_REQUIRE_MESSAGE(role.ok, why);

    const auto product =
        exports::BuildProductV1({role}, {});
    BOOST_REQUIRE_MESSAGE(
        product.all_supplied_artifacts_valid,
        product.note);
    BOOST_CHECK_EQUAL(
        product.preexisting_literal_endpoints, 26U);
    // Route literals are inventory only. All four Wiring endpoints become
    // proof-owned only because this role artifact is executed and rebuilt.
    BOOST_CHECK_EQUAL(
        product.newly_executed_export_endpoints, 4U);
    BOOST_CHECK_EQUAL(
        product.literal_proof_owned_endpoints, 4U);
    BOOST_CHECK_EQUAL(product.residual_endpoints, 48U);
    std::string validation;
    BOOST_CHECK_MESSAGE(
        exports::ValidateProductV1(
            product, &validation),
        validation);

    auto duplicate =
        exports::BuildProductV1({role, role}, {});
    duplicate.no_duplicate_roles = true;
    duplicate.all_supplied_artifacts_valid = true;
    BOOST_CHECK(
        !exports::ValidateProductV1(
            duplicate, &validation));
    BOOST_CHECK_NE(
        validation.find("duplicate_role"),
        std::string::npos);

    auto route_attack = product;
    route_attack.role_proofs.front()
        .exports.front().route.kind =
        exports::ProducerKindV1::WiredLedger;
    BOOST_CHECK(
        !exports::ValidateProductV1(
            route_attack, &validation));
    BOOST_CHECK_NE(
        validation.find("role_export_route"),
        std::string::npos);

    const auto& proof = product.role_proofs.front();
    BOOST_REQUIRE(proof.valid);
    BOOST_CHECK_EQUAL(proof.exports.size(), 4U);
    for (const auto& item : proof.exports) {
        BOOST_CHECK(item.role_air_witness_executed);
        BOOST_CHECK(item.same_trace_root_equality);
        BOOST_CHECK(item.canonical_u32_limbs);
        BOOST_CHECK(!item.recursively_consumed);
    }
}

BOOST_AUTO_TEST_CASE(
    route_literal_without_validated_role_receipt_gets_zero_credit)
{
    const auto product =
        exports::BuildProductV1({}, {});
    BOOST_CHECK(product.exact_inventory);
    BOOST_CHECK_EQUAL(
        product.preexisting_literal_endpoints, 26U);
    BOOST_CHECK_EQUAL(
        product.literal_proof_owned_endpoints, 0U);
    BOOST_CHECK_EQUAL(
        product.newly_executed_export_endpoints, 0U);
    BOOST_CHECK_EQUAL(product.residual_endpoints, 52U);
    BOOST_CHECK(product.semantic_ctl_cells.empty());
    std::string why;
    BOOST_CHECK_MESSAGE(
        exports::ValidateProductV1(product, &why), why);

    auto forged = product;
    BOOST_REQUIRE(
        forged.endpoints.front()
            .route.preexisting_literal);
    forged.endpoints.front()
        .literal_proof_owned_export = true;
    forged.literal_proof_owned_endpoints = 1;
    forged.newly_executed_export_endpoints = 1;
    forged.residual_endpoints = 51;
    BOOST_CHECK(
        !exports::ValidateProductV1(
            forged, &why));
    BOOST_CHECK_NE(
        why.find("endpoint_evidence"),
        std::string::npos);
}

BOOST_AUTO_TEST_CASE(
    source_omission_role_alias_root_and_temporal_order_reject)
{
    std::string why;
    const gf::Fp3 copy =
        gf::Fp3::FromFp(gf::FromU64(0x112233U));
    rc::RCStage3RoleAirProduct role =
        rc::BuildRCStage3EpisodeWiringRoleAir(
            &why, &copy);
    BOOST_REQUIRE_MESSAGE(role.ok, why);

    auto omitted = role;
    omitted.endpoints.pop_back();
    BOOST_CHECK(
        !exports::BuildProductV1(
             {omitted}, {}).all_supplied_artifacts_valid);

    auto role_alias = role;
    role_alias.role =
        rc::RCStage3RelationRole::CoupledPermutation;
    BOOST_CHECK(
        !exports::BuildProductV1(
             {role_alias}, {}).all_supplied_artifacts_valid);

    auto root = role;
    root.endpoint_committed_roots[1][0] =
        gf::Add(
            root.endpoint_committed_roots[1][0],
            gf::FromU64(1));
    BOOST_CHECK(
        !exports::BuildProductV1(
             {root}, {}).all_supplied_artifacts_valid);

    auto temporal = role;
    std::swap(
        temporal.endpoints[1],
        temporal.endpoints[2]);
    std::swap(
        temporal.endpoint_committed_roots[1],
        temporal.endpoint_committed_roots[2]);
    BOOST_CHECK(
        !exports::BuildProductV1(
             {temporal}, {}).all_supplied_artifacts_valid);
}

BOOST_AUTO_TEST_CASE(
    same_trace_export_limb_and_x_plus_p_attacks_reject)
{
    std::string why;
    const gf::Fp3 copy =
        gf::Fp3::FromFp(gf::FromU64(0x445566U));
    const rc::RCStage3RoleAirProduct role =
        rc::BuildRCStage3EpisodeWiringRoleAir(
            &why, &copy);
    BOOST_REQUIRE_MESSAGE(role.ok, why);
    auto product =
        exports::BuildProductV1({role}, {});
    BOOST_REQUIRE(product.all_supplied_artifacts_valid);
    BOOST_REQUIRE(!product.role_proofs.empty());
    auto& proof = product.role_proofs.front();
    BOOST_REQUIRE(proof.valid);
    BOOST_REQUIRE(!proof.exports.empty());

    const uint32_t value_col =
        proof.exports.front().export_word_base;
    proof.columns[value_col][0] =
        gf::Add(
            proof.columns[value_col][0],
            gf::Fp3::One());
    BOOST_CHECK_GT(
        matmul::v4::rc::air_recurse::
            CountWitnessViolationsOnH(
            proof.cs, proof.columns),
        0U);
    BOOST_CHECK(
        !exports::ValidateRoleExportProofV1(
            proof, &why));

    product =
        exports::BuildProductV1({role}, {});
    auto& alias = product.role_proofs.front();
    const uint32_t raw_col =
        alias.exports.front().export_word_base;
    alias.columns[raw_col][0].c0 += gf::kP;
    // Field arithmetic would identify x+p with x; the raw canonical check
    // must still reject it before proof verification.
    BOOST_CHECK(
        !exports::ValidateRoleExportProofV1(
            alias, &why));

    product =
        exports::BuildProductV1({role}, {});
    auto& simultaneous = product.role_proofs.front();
    auto& item = simultaneous.exports.front();
    const uint32_t old_word = item.root_words[0];
    const uint32_t new_word = old_word ^ 1U;
    item.root_words[0] = new_word;
    const uint64_t new_lane =
        static_cast<uint64_t>(new_word) |
        (static_cast<uint64_t>(item.root_words[1]) << 32);
    item.committed_root[0] = gf::FromU64(new_lane);
    const gf::Fp3 new_value =
        gf::Fp3::FromFp(gf::FromU64(new_word));
    for (uint32_t row = 0; row < simultaneous.cs.n_rows; ++row) {
        simultaneous.columns[item.export_word_base][row] =
            new_value;
        simultaneous.columns[item.export_word_base + 1U][row] =
            new_value;
        for (uint32_t bit = 0; bit < 32; ++bit) {
            simultaneous.columns[
                item.export_bits_base + bit][row] =
                gf::Fp3::FromFp(
                    gf::FromU64(
                        (new_word >> bit) & 1U));
        }
    }
    // The old source CS still accepts its old witness and the attacker has
    // changed both equality sides consistently. Canonical source-CS
    // regeneration from the claimed new root must nevertheless reject.
    BOOST_CHECK_EQUAL(
        matmul::v4::rc::air_recurse::
            CountWitnessViolationsOnH(
                simultaneous.cs,
                simultaneous.columns),
        0U);
    BOOST_CHECK(
        !exports::ValidateRoleExportProofV1(
            simultaneous, &why));
}

BOOST_AUTO_TEST_CASE(
    stream_root_is_not_promoted_without_executed_heavy_child)
{
    std::string why;
    std::vector<std::array<uint32_t, 8>> roots(4);
    for (uint32_t endpoint = 0; endpoint < roots.size(); ++endpoint) {
        for (uint32_t word = 0; word < 8; ++word) {
            roots[endpoint][word] =
                0x1000U * (endpoint + 1U) + word;
        }
    }
    const auto role =
        rc::BuildRCStage3PureStreamRoleAirFromRoots(
            rc::RCStage3RelationRole::EpisodeTileTree,
            roots, &why);
    BOOST_REQUIRE_MESSAGE(role.ok, why);

    const auto product =
        exports::BuildProductV1({role}, {});
    BOOST_REQUIRE(product.all_supplied_artifacts_valid);
    BOOST_CHECK_EQUAL(
        product.newly_executed_export_endpoints, 0U);
    for (const auto& endpoint : product.endpoints) {
        if (endpoint.route.role !=
            rc::RCStage3RelationRole::EpisodeTileTree) {
            continue;
        }
        BOOST_CHECK(endpoint.supplied_role_artifact);
        BOOST_CHECK(endpoint.executed_role_artifact);
        BOOST_CHECK(!endpoint.executed_stream_child);
        BOOST_CHECK(!endpoint.literal_proof_owned_export);
        BOOST_CHECK(
            endpoint.residual.find("heavy stream child") !=
            std::string::npos);
    }
}

BOOST_AUTO_TEST_CASE(
    executed_stream_child_promotes_only_its_exact_root)
{
    using Endpoint = rc::RCStage3RelationEndpoint;
    const Endpoint endpoint =
        Endpoint::EpisodeTileTreeStream;
    const rc::RCStage3StreamFamily family =
        rc::RCStage3StreamFamilyForEndpoint(endpoint);
    std::array<uint32_t, 8> stream_value{};
    for (uint32_t word = 0; word < stream_value.size(); ++word) {
        stream_value[word] = 0x760000U + 13U * word;
    }
    const auto manifest =
        rc::BuildRCStage3StreamEndpointCanonicalManifest(
            family, stream_value, 0, 1);
    uint256 seed;
    for (uint32_t byte = 0; byte < 32; ++byte) {
        seed.begin()[byte] =
            static_cast<unsigned char>(9U * byte + 1U);
    }
    std::string why;
    const auto closure =
        rc::RCStage3StreamEndpointClose(
            family, manifest, seed, &why, true);
    BOOST_REQUIRE_MESSAGE(closure.ok, why);
    BOOST_CHECK_EQUAL(closure.child_violations, 0U);
    BOOST_CHECK_EQUAL(closure.bind_violations, 0U);

    std::vector<std::array<uint32_t, 8>> roots(4);
    roots[0] = closure.committed_root;
    for (uint32_t i = 1; i < roots.size(); ++i) {
        for (uint32_t word = 0; word < 8; ++word) {
            roots[i][word] =
                0x880000U + i * 0x1000U + word;
        }
    }
    const auto role =
        rc::BuildRCStage3PureStreamRoleAirFromRoots(
            rc::RCStage3RelationRole::EpisodeTileTree,
            roots, &why);
    BOOST_REQUIRE_MESSAGE(role.ok, why);

    exports::StreamChildArtifactV1 child;
    child.endpoint = endpoint;
    child.closure = closure;
    const auto product =
        exports::BuildProductV1({role}, {child});
    BOOST_REQUIRE(product.all_supplied_artifacts_valid);
    BOOST_CHECK_EQUAL(
        product.newly_executed_export_endpoints, 1U);
    BOOST_CHECK_EQUAL(
        product.literal_proof_owned_endpoints, 1U);
    BOOST_CHECK_EQUAL(product.residual_endpoints, 51U);

    auto v2_child_on_v1_role = child;
    v2_child_on_v1_role.closure
        .semantic_export_version =
        rc::kRCStage3StreamEndpointSemanticExportVersionV2;
    const auto substituted_v2_child =
        exports::BuildProductV1(
            {role}, {v2_child_on_v1_role});
    BOOST_CHECK_EQUAL(
        substituted_v2_child
            .newly_executed_export_endpoints,
        0U);

    rc::air_quotient::AirConstraintSystem<gf::Fp3>
        exact_cs;
    BOOST_REQUIRE_MESSAGE(
        rc::BuildRCStage3PureStreamRoleAirCSV2(
            rc::RCStage3RelationRole::
                EpisodeTileTree,
            roots, exact_cs, &why),
        why);
    std::vector<std::vector<gf::Fp3>>
        exact_witness;
    for (uint32_t endpoint_index = 0;
         endpoint_index < roots.size();
         ++endpoint_index) {
        const auto fragment =
            rc::BuildRCStage3StreamEndpointWitness(
                roots[endpoint_index],
                endpoint_index == 0
                    ? rc::RCStage3StreamEndpointCtlValue(
                          manifest)
                    : gf::Fp3::Zero());
        exact_witness.insert(
            exact_witness.end(),
            fragment.begin(), fragment.end());
        for (uint32_t word = 0; word < 8U; ++word) {
            for (uint32_t bit = 0; bit < 32U; ++bit) {
                exact_witness.push_back(
                    std::vector<gf::Fp3>(
                        2,
                        gf::Fp3::FromFp(
                            gf::FromU64(
                                (roots[endpoint_index][word] >>
                                 bit) &
                                1U))));
            }
        }
    }
    rc::RCStage3RoleAirProduct exact_role;
    exact_role.role =
        rc::RCStage3RelationRole::EpisodeTileTree;
    exact_role.semantic_root_abi_version =
        rc::kRCStage3ExactU32StreamRootAbiVersionV2;
    exact_role.cs = exact_cs;
    exact_role.witness = std::move(exact_witness);
    exact_role.endpoints =
        rc::RequiredRCStage3RelationEndpoints(
            exact_role.role);
    exact_role.endpoint_committed_root_words_v2 =
        roots;
    exact_role.opening_blocks =
        static_cast<uint32_t>(roots.size());
    exact_role.ok = true;
    const auto substituted_v1_child =
        exports::BuildProductV1(
            {exact_role}, {child});
    BOOST_CHECK_EQUAL(
        substituted_v1_child
            .newly_executed_export_endpoints,
        0U);

    auto wrong_root_role = role;
    wrong_root_role.endpoint_committed_roots[0][0] =
        gf::Add(
            wrong_root_role.endpoint_committed_roots[0][0],
            gf::FromU64(1));
    const auto wrong_root =
        exports::BuildProductV1(
            {wrong_root_role}, {child});
    BOOST_CHECK(
        !wrong_root.all_supplied_artifacts_valid ||
        wrong_root.newly_executed_export_endpoints == 0U);
}

BOOST_AUTO_TEST_CASE(
    exact_u32_stream_role_v2_does_not_alias_x_plus_p)
{
    using Role = rc::RCStage3RelationRole;
    const Role role = Role::EpisodeTileTree;
    const auto& endpoints =
        rc::RequiredRCStage3RelationEndpoints(role);
    std::vector<std::array<uint32_t, 8>> roots(
        endpoints.size());
    for (uint32_t endpoint = 0;
         endpoint < roots.size(); ++endpoint) {
        for (uint32_t word = 0;
             word < roots[endpoint].size(); ++word) {
            roots[endpoint][word] =
                0x1000U + endpoint * 0x100U + word;
        }
    }
    // p = 0xffffffff00000001. The first packed-u64 pair below is p+1,
    // which the frozen four-Fp-lane ABI canonicalizes to 1. V2 retains the
    // exact words {2, 0xffffffff} as two independent u32 lanes.
    roots[0][0] = 2U;
    roots[0][1] = 0xffffffffU;
    auto alias_roots = roots;
    alias_roots[0][0] = 1U;
    alias_roots[0][1] = 0U;

    rc::air_quotient::AirConstraintSystem<gf::Fp3> cs;
    rc::air_quotient::AirConstraintSystem<gf::Fp3>
        alias_cs;
    std::string why;
    BOOST_REQUIRE_MESSAGE(
        rc::BuildRCStage3PureStreamRoleAirCSV2(
            role, roots, cs, &why),
        why);
    BOOST_REQUIRE_MESSAGE(
        rc::BuildRCStage3PureStreamRoleAirCSV2(
            role, alias_roots, alias_cs, &why),
        why);
    BOOST_CHECK_EQUAL(
        cs.n_columns,
        endpoints.size() *
            rc::kRCStage3ExactU32StreamRoleEndpointStrideV2);

    std::vector<std::vector<gf::Fp3>> witness;
    for (uint32_t endpoint = 0;
         endpoint < roots.size(); ++endpoint) {
        const auto fragment =
            rc::BuildRCStage3StreamEndpointWitness(
                roots[endpoint], gf::Fp3::Zero());
        witness.insert(
            witness.end(),
            fragment.begin(), fragment.end());
        for (uint32_t word = 0; word < 8U; ++word) {
            for (uint32_t bit = 0; bit < 32U; ++bit) {
                witness.push_back(
                    std::vector<gf::Fp3>(
                        2,
                        gf::Fp3::FromFp(
                            gf::FromU64(
                                (roots[endpoint][word] >>
                                 bit) &
                                1U))));
            }
        }
    }
    BOOST_REQUIRE_EQUAL(
        witness.size(), cs.n_columns);
    BOOST_CHECK_EQUAL(
        rc::air_recurse::CountWitnessViolationsOnH(
            cs, witness),
        0U);
    BOOST_CHECK_GT(
        rc::air_recurse::CountWitnessViolationsOnH(
            alias_cs, witness),
        0U);

    rc::RCStage3RoleAirProduct artifact;
    artifact.role = role;
    artifact.semantic_root_abi_version =
        rc::kRCStage3ExactU32StreamRootAbiVersionV2;
    artifact.cs = cs;
    artifact.witness = witness;
    artifact.endpoints = endpoints;
    artifact.endpoint_committed_root_words_v2 =
        roots;
    artifact.fragment_columns = 0;
    artifact.opening_blocks =
        static_cast<uint32_t>(endpoints.size());
    artifact.ok = true;
    const auto honest =
        exports::BuildProductV1({artifact}, {});
    BOOST_REQUIRE_MESSAGE(
        exports::ValidateProductV1(
            honest, &why),
        why);

    // Field arithmetic alone reduces this raw p alias. The consensus-facing
    // V2 validator must reject its noncanonical representation explicitly.
    artifact.witness[
        rc::kRCStage3ExactU32StreamRoleRootWordBaseV2]
        [0]
        .c0 += gf::kP;
    const auto noncanonical =
        exports::BuildProductV1({artifact}, {});
    BOOST_CHECK(
        !exports::ValidateProductV1(
            noncanonical, &why));
}

BOOST_AUTO_TEST_SUITE_END()
