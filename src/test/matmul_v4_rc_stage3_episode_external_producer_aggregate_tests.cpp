// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <boost/test/unit_test.hpp>

#include <matmul/matmul_v4_rc_stage3_episode_external_producer_aggregate.h>

#include <algorithm>

namespace {

namespace rc = matmul::v4::rc;
namespace aggregate =
    rc::episode_external_producer_aggregate;
namespace source =
    rc::episode_semantic_source_alg;
namespace gf = rc::gkr_field;

uint256 H(unsigned char tag)
{
    uint256 out;
    std::fill(out.begin(), out.end(), tag);
    return out;
}

struct Fixture {
    rc::RCStage3GemmExtractLayerManifest spec;
    source::LayerShapeV1 shape;
    rc::RCStage3EpisodeGemmLayerProduct layer;
    rc::RCStage3EpisodeExtractProduct extract;
    source::LayerBundleV1 bundle;
};

Fixture BuildFixture(int8_t operand_a)
{
    Fixture out;
    out.spec.ordinal = 7;
    out.spec.m = 1;
    out.spec.n = 64;
    out.spec.k = 1;
    out.spec.b.transpose = false;
    out.spec.gemm_cell_count = 64;
    out.spec.extract_tile_begin = 0;
    out.spec.extract_tile_count = 2;
    out.spec.signed_max_abs = 1U << 20;

    std::string why;
    BOOST_REQUIRE_MESSAGE(
        source::BuildLayerShapeV1(
            H(0x51), H(0x62), out.spec,
            out.shape, &why),
        why);
    out.layer.layer_ordinal = out.spec.ordinal;
    out.layer.operand_a = {operand_a};
    out.layer.operand_b.resize(64);
    out.layer.gemm_y.resize(64);
    for (uint32_t i = 0; i < 64; ++i) {
        const int8_t b =
            static_cast<int8_t>(
                static_cast<int32_t>(i % 7U) - 3);
        out.layer.operand_b[i] = b;
        out.layer.gemm_y[i] =
            static_cast<int64_t>(operand_a) * b;
    }
    out.extract.expected_tiles = 2;
    out.extract.tiles.resize(2);
    for (uint32_t tile = 0; tile < 2; ++tile) {
        out.extract.tiles[tile].global_tile = tile;
        out.extract.tiles[tile].layer_ordinal =
            out.spec.ordinal;
        out.extract.tiles[tile].layer_tile_index =
            tile;
        for (uint32_t lane = 0;
             lane < rc::kRCMxBlockLen; ++lane) {
            out.extract.tiles[tile].input[lane] =
                out.layer.gemm_y[
                    tile * rc::kRCMxBlockLen +
                    lane];
        }
    }
    BOOST_REQUIRE_MESSAGE(
        source::ProveLayerBundleV1(
            out.shape, out.layer, out.extract,
            0, out.bundle, &why),
        why);
    return out;
}

} // namespace

BOOST_AUTO_TEST_SUITE(
    matmul_v4_rc_stage3_episode_external_producer_aggregate_tests)

BOOST_AUTO_TEST_CASE(
    four_proof_owned_ingress_children_close_local_layer_only)
{
    const Fixture fixture = BuildFixture(2);
    aggregate::LayerClosureV1 closure;
    std::string why;
    BOOST_REQUIRE_MESSAGE(
        aggregate::ProveLayerClosureV1(
            fixture.shape, fixture.spec,
            fixture.layer, fixture.extract, 0,
            fixture.bundle, 0, closure, &why),
        why);
    BOOST_REQUIRE_MESSAGE(
        aggregate::VerifyLayerClosureV1(
            fixture.shape, fixture.bundle,
            0,
            closure.operand_a_vector_root_alg,
            closure.operand_b_vector_root_alg,
            closure, &why),
        why);
    BOOST_CHECK(closure.exact_projection_set);
    BOOST_CHECK(closure.all_children_proof_verified);
    BOOST_CHECK(closure.all_r0_before_challenge);
    BOOST_CHECK(closure.exact_producer_coverage);
    BOOST_CHECK(closure.exact_consumer_coverage);
    BOOST_CHECK(
        closure.proof_owned_terminal_cancellation);
    BOOST_CHECK(
        !closure.role_export_equality_constrained);
    BOOST_CHECK(!closure.recursive_child_consumed);
    BOOST_CHECK(!closure.semantic_closure);
    BOOST_CHECK(!closure.production_authority);
    BOOST_CHECK(!closure.closure_commitment.IsNull());

    auto reordered_layer = closure;
    ++reordered_layer.consumer_leaf_begin;
    BOOST_CHECK(
        !aggregate::VerifyLayerClosureV1(
            fixture.shape, fixture.bundle,
            0,
            closure.operand_a_vector_root_alg,
            closure.operand_b_vector_root_alg,
            reordered_layer, &why));

    auto omitted = closure;
    omitted.operand_a_external
        .producer_children.pop_back();
    BOOST_CHECK(
        !aggregate::VerifyLayerClosureV1(
            fixture.shape, fixture.bundle,
            0,
            closure.operand_a_vector_root_alg,
            closure.operand_b_vector_root_alg,
            omitted, &why));

    auto duplicated = closure;
    duplicated.operand_a_external
        .producer_children.push_back(
            duplicated.operand_a_external
                .producer_children.back());
    BOOST_CHECK(
        !aggregate::VerifyLayerClosureV1(
            fixture.shape, fixture.bundle,
            0,
            closure.operand_a_vector_root_alg,
            closure.operand_b_vector_root_alg,
            duplicated, &why));

    auto swapped = closure;
    std::swap(
        swapped.operand_a_external,
        swapped.operand_b_external);
    BOOST_CHECK(
        !aggregate::VerifyLayerClosureV1(
            fixture.shape, fixture.bundle,
            0,
            closure.operand_a_vector_root_alg,
            closure.operand_b_vector_root_alg,
            swapped, &why));

    auto authority_claim = closure;
    authority_claim.role_export_equality_constrained =
        true;
    authority_claim.semantic_closure = true;
    authority_claim.production_authority = true;
    BOOST_CHECK(
        !aggregate::VerifyLayerClosureV1(
            fixture.shape, fixture.bundle,
            0,
            closure.operand_a_vector_root_alg,
            closure.operand_b_vector_root_alg,
            authority_claim, &why));

    auto proof_attack = closure;
    BOOST_REQUIRE(
        !proof_attack.operand_a_gemm
             .producer_children.empty());
    BOOST_REQUIRE(
        !proof_attack.operand_a_gemm
             .producer_children[0]
             .proof.batch.queries.empty());
    BOOST_REQUIRE(
        !proof_attack.operand_a_gemm
             .producer_children[0]
             .proof.batch.queries[0]
             .group_rows.empty());
    BOOST_REQUIRE(
        !proof_attack.operand_a_gemm
             .producer_children[0]
             .proof.batch.queries[0]
             .group_rows[0].values.empty());
    auto& attacked =
        proof_attack.operand_a_gemm
            .producer_children[0]
            .proof.batch.queries[0]
            .group_rows[0].values[0];
    attacked = gf::Add(attacked, gf::Fp3::One());
    BOOST_CHECK(
        !aggregate::VerifyLayerClosureV1(
            fixture.shape, fixture.bundle,
            0,
            closure.operand_a_vector_root_alg,
            closure.operand_b_vector_root_alg,
            proof_attack, &why));
}

BOOST_AUTO_TEST_CASE(
    separately_valid_layer_closure_cannot_be_transplanted)
{
    const Fixture honest = BuildFixture(2);
    const Fixture alternate = BuildFixture(-3);
    aggregate::LayerClosureV1 honest_closure;
    aggregate::LayerClosureV1 alternate_closure;
    std::string why;
    BOOST_REQUIRE_MESSAGE(
        aggregate::ProveLayerClosureV1(
            honest.shape, honest.spec,
            honest.layer, honest.extract, 0,
            honest.bundle, 0,
            honest_closure, &why),
        why);
    BOOST_REQUIRE_MESSAGE(
        aggregate::ProveLayerClosureV1(
            alternate.shape, alternate.spec,
            alternate.layer, alternate.extract, 0,
            alternate.bundle, 0,
            alternate_closure,
            &why),
        why);
    BOOST_REQUIRE(
        honest_closure.operand_a_vector_root_alg !=
        alternate_closure.operand_a_vector_root_alg);

    auto transplanted = honest_closure;
    transplanted.operand_a_external =
        alternate_closure.operand_a_external;
    transplanted.operand_a_gemm =
        alternate_closure.operand_a_gemm;
    BOOST_CHECK(
        !aggregate::VerifyLayerClosureV1(
            honest.shape, honest.bundle,
            0,
            honest_closure.operand_a_vector_root_alg,
            honest_closure.operand_b_vector_root_alg,
            transplanted, &why));
}

BOOST_AUTO_TEST_SUITE_END()
