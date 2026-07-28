// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <boost/test/unit_test.hpp>

#include <matmul/matmul_v4_rc_stage3_episode_semantic_source_alg.h>

#include <algorithm>
#include <type_traits>

namespace {

namespace rc = matmul::v4::rc;
namespace source =
    matmul::v4::rc::episode_semantic_source_alg;
namespace aq = matmul::v4::rc::air_quotient;
namespace gf = matmul::v4::rc::gkr_field;

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

Fixture BuildFixture()
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

    std::string why;
    BOOST_REQUIRE_MESSAGE(
        source::BuildLayerShapeV1(
            H(0x11), H(0x22), out.spec,
            out.shape, &why),
        why);

    out.layer.layer_ordinal = out.spec.ordinal;
    out.layer.operand_a = {2};
    out.layer.operand_b.resize(64);
    out.layer.gemm_y.resize(64);
    for (uint32_t i = 0; i < 64; ++i) {
        const int8_t b =
            static_cast<int8_t>(
                static_cast<int32_t>(i % 7) - 3);
        out.layer.operand_b[i] = b;
        out.layer.gemm_y[i] =
            static_cast<int64_t>(2) * b;
    }
    out.extract.tiles.resize(2);
    for (uint32_t tile = 0; tile < 2; ++tile) {
        for (uint32_t lane = 0;
             lane < rc::kRCMxBlockLen; ++lane) {
            out.extract.tiles[tile].input[lane] =
                out.layer.gemm_y[
                    tile * rc::kRCMxBlockLen + lane];
        }
    }
    BOOST_REQUIRE_MESSAGE(
        source::ProveLayerBundleV1(
            out.shape, out.layer, out.extract,
            0, out.bundle, &why),
        why);
    return out;
}

const Fixture& SharedFixture()
{
    static const Fixture fixture =
        BuildFixture();
    return fixture;
}

} // namespace

BOOST_AUTO_TEST_SUITE(
    matmul_v4_rc_stage3_episode_semantic_source_alg_tests)

BOOST_AUTO_TEST_CASE(
    sharded_ordinary_leaf_directly_owns_A_B_Y_cells)
{
    static_assert(std::is_same_v<
        source::AlgAirProof,
        aq::AirQuotientProof<
            gf::Fp3,
            aq::AirFriBackendAlg<gf::Fp3>>>);

    const Fixture& fixture = SharedFixture();
    BOOST_REQUIRE_EQUAL(fixture.bundle.leaves.size(), 1U);
    const auto& leaf = fixture.bundle.leaves.front();
    BOOST_CHECK_EQUAL(leaf.manifest.tile_begin, 0U);
    BOOST_CHECK_EQUAL(leaf.manifest.tile_count, 2U);
    BOOST_CHECK_EQUAL(leaf.manifest.tile_rows, 32U);
    BOOST_CHECK_EQUAL(leaf.manifest.logical_rows, 64U);
    BOOST_CHECK_EQUAL(
        leaf.manifest.n_rows, 64U);

    const auto& projections =
        source::CanonicalSourceProjectionsV1();
    BOOST_CHECK_EQUAL(
        projections[source::kOperandASlotV1].value_column,
        rc::kRCStage3GemmDotA);
    BOOST_CHECK_EQUAL(
        projections[source::kOperandBSlotV1].value_column,
        rc::kRCStage3GemmDotB);
    BOOST_CHECK_EQUAL(
        projections[source::kOutputYSlotV1].value_column,
        rc::kRCStage3GemmDotY);
    for (const auto& projection : projections) {
        BOOST_CHECK_LT(
            projection.value_column,
            source::kMetadataColumnBaseV1);
    }

    const source::VerificationInputV1 input =
        source::BuildVerificationInputV1(leaf);
    BOOST_REQUIRE_MESSAGE(input.valid, input.note);
    BOOST_REQUIRE(input.proof != nullptr);
    BOOST_CHECK(!input.node_root.IsNull());
    BOOST_CHECK(!input.program_root.IsNull());
    BOOST_CHECK(!input.proof_context_root.IsNull());
    BOOST_CHECK(!input.statement_commitment.IsNull());
    BOOST_CHECK(!input.expected_cs_commitment.IsNull());
    BOOST_CHECK(!input.proof_commitment.IsNull());
    BOOST_CHECK(!input.canonical_proof_bytes.empty());
    BOOST_CHECK_EQUAL(input.active_rows, 64U);
    BOOST_CHECK_GT(input.n_lde, input.active_rows);

    const auto audit =
        source::VerifyLayerBundleV1(
            fixture.shape, fixture.bundle);
    BOOST_REQUIRE_MESSAGE(audit.accepted, audit.note);
    BOOST_CHECK_EQUAL(audit.verified_tiles, 2U);
    BOOST_CHECK_EQUAL(audit.covered_operand_a, 1U);
    BOOST_CHECK_EQUAL(audit.covered_operand_b, 64U);
    BOOST_CHECK_EQUAL(audit.covered_output_y, 64U);
    BOOST_CHECK(audit.source_owned);
    BOOST_CHECK(audit.receiver_owned);
    BOOST_CHECK(audit.dual_alpha_ctl_terminal);
    BOOST_CHECK(audit.terminal_join);
    BOOST_CHECK(audit.source_terminal_proof_owned);
    BOOST_CHECK(!audit.external_producer_terminal_joined);
    BOOST_CHECK(!audit.strict_transitive_provenance);
    BOOST_CHECK(!audit.production_source_closed);
}

BOOST_AUTO_TEST_CASE(
    proof_level_query_and_trace_root_attacks_reject)
{
    const Fixture& fixture = SharedFixture();
    const auto& receipt = fixture.bundle.leaves.front();
    source::VerificationInputV1 input =
        source::BuildVerificationInputV1(receipt);
    BOOST_REQUIRE_MESSAGE(input.valid, input.note);
    BOOST_REQUIRE(input.proof != nullptr);

    auto query_attack = *input.proof;
    BOOST_REQUIRE(!query_attack.batch.queries.empty());
    BOOST_REQUIRE(
        query_attack.batch.queries[0]
            .row.values.size() >
        rc::kRCStage3GemmDotA);
    query_attack.batch.queries[0]
        .row.values[rc::kRCStage3GemmDotA] =
        gf::Add(
            query_attack.batch.queries[0]
                .row.values[rc::kRCStage3GemmDotA],
            gf::Fp3::One());
    std::string why;
    BOOST_CHECK(
        (!aq::AirQuotientVerify<
            gf::Fp3,
            aq::AirFriBackendAlg<gf::Fp3>>(
                input.expected_cs, query_attack,
                input.public_fs_seed, &why)));

    auto root_attack = *input.proof;
    root_attack.trace_commit.begin()[0] ^= 1U;
    BOOST_CHECK(
        (!aq::AirQuotientVerify<
            gf::Fp3,
            aq::AirFriBackendAlg<gf::Fp3>>(
                input.expected_cs, root_attack,
                input.public_fs_seed, &why)));
}

BOOST_AUTO_TEST_CASE(
    same_parent_source_and_receiver_value_attacks_reject_at_proof_level)
{
    const Fixture& fixture = SharedFixture();
    const auto& leaf =
        fixture.bundle.leaves.front();
    BOOST_REQUIRE_EQUAL(
        leaf.same_parent_ctl_joins.size(),
        source::kEndpointCountV1);
    const auto& join =
        leaf.same_parent_ctl_joins[
            source::kOperandASlotV1];
    const auto input =
        source::BuildSameParentCtlVerificationInputV1(
            leaf.manifest, join);
    BOOST_REQUIRE_MESSAGE(input.valid, input.note);
    BOOST_REQUIRE(input.proof != nullptr);
    BOOST_REQUIRE(
        !input.proof->batch.queries.empty());
    BOOST_REQUIRE(
        !input.proof->batch.queries[0]
             .group_rows.empty());
    BOOST_REQUIRE_GT(
        input.proof->batch.queries[0]
            .group_rows[0].values.size(),
        source::kTotalColumnsV1 +
            rc::kRCStage3EpisodeMemoryValue);

    const auto& projection =
        source::CanonicalSourceProjectionsV1()[
            source::kOperandASlotV1];
    auto source_value_attack =
        *input.proof;
    source_value_attack.batch.queries[0]
        .group_rows[0]
        .values[
            projection.semantic_value_column] =
        gf::Add(
            source_value_attack.batch.queries[0]
                .group_rows[0]
                .values[
                    projection.semantic_value_column],
            gf::Fp3::One());
    std::string why;
    BOOST_CHECK(
        !aq::AirQuotientVerifyRowsSplitRapSafeV2(
            input.expected_cs,
            source_value_attack,
            input.expected_base_column_indices,
            input.public_fs_seed, &why));

    auto receiver_value_attack =
        *input.proof;
    const uint32_t receiver_value_column =
        source::kTotalColumnsV1 +
        rc::kRCStage3EpisodeMemoryValue;
    receiver_value_attack.batch.queries[0]
        .group_rows[0]
        .values[receiver_value_column] =
        gf::Add(
            receiver_value_attack.batch.queries[0]
                .group_rows[0]
                .values[receiver_value_column],
            gf::Fp3::One());
    BOOST_CHECK(
        !aq::AirQuotientVerifyRowsSplitRapSafeV2(
            input.expected_cs,
            receiver_value_attack,
            input.expected_base_column_indices,
            input.public_fs_seed, &why));

    auto root_attack = join;
    root_attack.base_row_commitment.begin()[0] ^= 1U;
    BOOST_CHECK(
        !source::VerifySameParentCtlJoinV1(
            leaf.manifest, root_attack, &why));

    auto terminal_attack = join;
    terminal_attack.receiver_terminal.alpha1_sum =
        gf::Add(
            terminal_attack.receiver_terminal
                .alpha1_sum,
            gf::Fp3::One());
    BOOST_CHECK(
        !source::VerifySameParentCtlJoinV1(
            leaf.manifest, terminal_attack, &why));
}

BOOST_AUTO_TEST_CASE(
    omission_reorder_transplant_and_schedule_attacks_reject)
{
    const Fixture& fixture = SharedFixture();
    std::string why;

    auto omitted = fixture.bundle;
    omitted.leaves.clear();
    BOOST_CHECK(
        !source::VerifyLayerBundleV1(
             fixture.shape, omitted)
             .accepted);

    // The canonical partition is one two-tile shard. Splitting and reversing
    // it is rejected before any host-selected inventory can become authority.
    source::LeafManifestV1 first;
    source::LeafManifestV1 second;
    BOOST_REQUIRE_MESSAGE(
        source::BuildLeafManifestV1(
            fixture.shape, 0, 1, first, &why),
        why);
    BOOST_REQUIRE_MESSAGE(
        source::BuildLeafManifestV1(
            fixture.shape, 1, 1, second, &why),
        why);
    auto reordered = fixture.bundle;
    reordered.leaves = {
        fixture.bundle.leaves.front(),
        fixture.bundle.leaves.front()};
    reordered.leaves[0].manifest = second;
    reordered.leaves[1].manifest = first;
    BOOST_CHECK(
        !source::VerifyLayerBundleV1(
             fixture.shape, reordered)
             .accepted);

    auto schedule_attack =
        fixture.bundle.leaves.front();
    schedule_attack.manifest.schedule_commitment.begin()[0] ^= 1U;
    BOOST_CHECK(
        !source::VerifyLeafV1(
            fixture.shape, 0, 2,
            schedule_attack, &why));

    auto transplanted_shape = fixture.shape;
    transplanted_shape.statement_commitment = H(0x99);
    transplanted_shape.shape_commitment =
        source::ComputeLayerShapeCommitmentV1(
            transplanted_shape);
    BOOST_CHECK(
        !source::VerifyLeafV1(
            transplanted_shape, 0, 2,
            fixture.bundle.leaves.front(), &why));
}

BOOST_AUTO_TEST_SUITE_END()
