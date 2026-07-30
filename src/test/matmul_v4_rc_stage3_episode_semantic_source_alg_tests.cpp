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

Fixture BuildFixture(int8_t operand_a = 2)
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
            H(0x11), H(0x22), out.spec,
            out.shape, &why),
        why);

    out.layer.layer_ordinal = out.spec.ordinal;
    out.layer.operand_a = {operand_a};
    out.layer.operand_b.resize(64);
    out.layer.gemm_y.resize(64);
    for (uint32_t i = 0; i < 64; ++i) {
        const int8_t b =
            static_cast<int8_t>(
                static_cast<int32_t>(i % 7) - 3);
        out.layer.operand_b[i] = b;
        out.layer.gemm_y[i] =
            static_cast<int64_t>(operand_a) * b;
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

std::vector<gf::Fp3> ToField(
    const std::vector<int8_t>& values)
{
    std::vector<gf::Fp3> out;
    out.reserve(values.size());
    for (int8_t value : values) {
        out.push_back(
            gf::FromSigned3(value));
    }
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
    BOOST_CHECK(
        leaf.proof.trace_commit ==
        leaf.unified_same_parent_ctl_join
            .source_trace_commitment);

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
    external_producer_shared_epoch_closes_all_A_and_B_shards)
{
    const Fixture& fixture = SharedFixture();
    for (uint32_t slot :
         {source::kOperandASlotV1,
          source::kOperandBSlotV1}) {
        const auto values =
            slot == source::kOperandASlotV1
            ? ToField(fixture.layer.operand_a)
            : ToField(fixture.layer.operand_b);
        const uint256 producer_root =
            rc::RCStage3VectorRootAlgCommitment(
                values);
        source::ExternalProducerClosureV3 closure;
        std::string why;
        BOOST_REQUIRE_MESSAGE(
            source::ProveExternalProducerClosureV3(
                fixture.shape, fixture.layer,
                fixture.extract, 0,
                fixture.bundle, slot,
                producer_root, closure, &why),
            why);
        BOOST_CHECK_MESSAGE(
            source::VerifyExternalProducerClosureV3(
                fixture.shape, fixture.bundle,
                slot, producer_root,
                closure, &why),
            why);
        BOOST_CHECK(
            closure.all_r0_before_challenge);
        BOOST_CHECK(
            closure.exact_producer_coverage);
        BOOST_CHECK(
            closure.exact_consumer_coverage);
        BOOST_CHECK(
            closure.proof_owned_terminal_cancellation);
        BOOST_CHECK(
            !closure.closure_commitment.IsNull());
        BOOST_REQUIRE_EQUAL(
            closure.manifest.participants.size(),
            2U);
        BOOST_CHECK_EQUAL(
            closure.manifest.participants[0]
                .receive_count,
            values.size());
        BOOST_CHECK_EQUAL(
            closure.manifest.participants[1]
                .send_count,
            values.size());
        for (const auto& child :
             closure.consumer_children) {
            BOOST_CHECK(
                !child.owning_r0_root.IsNull());
            BOOST_CHECK_EQUAL(
                child.proof.batch.groups.size(),
                3U);
            BOOST_CHECK(
                rc::Fri3AlgDigestToUint256(
                    child.proof.batch.groups[0]
                        .row_commit.root) ==
                child.owning_r0_root);
        }
        for (const auto& child :
             closure.producer_children) {
            BOOST_CHECK(
                !child.owning_r0_root.IsNull());
            BOOST_CHECK_EQUAL(
                child.proof.batch.groups.size(),
                3U);
            BOOST_CHECK(
                rc::Fri3AlgDigestToUint256(
                    child.proof.batch.groups[0]
                        .row_commit.root) ==
                child.owning_r0_root);
        }
    }
}

BOOST_AUTO_TEST_CASE(
    external_producer_rejects_coherent_valid_cross_witness_transplant)
{
    const Fixture honest = BuildFixture(2);
    const Fixture alternate = BuildFixture(-3);
    const uint256 honest_root =
        rc::RCStage3VectorRootAlgCommitment(
            ToField(honest.layer.operand_a));
    const uint256 alternate_root =
        rc::RCStage3VectorRootAlgCommitment(
            ToField(alternate.layer.operand_a));
    BOOST_REQUIRE(honest_root != alternate_root);

    source::ExternalProducerClosureV3 honest_closure;
    source::ExternalProducerClosureV3 alternate_closure;
    std::string why;
    BOOST_REQUIRE_MESSAGE(
        source::ProveExternalProducerClosureV3(
            honest.shape, honest.layer,
            honest.extract, 0, honest.bundle,
            source::kOperandASlotV1,
            honest_root, honest_closure, &why),
        why);
    BOOST_REQUIRE_MESSAGE(
        source::ProveExternalProducerClosureV3(
            alternate.shape, alternate.layer,
            alternate.extract, 0,
            alternate.bundle,
            source::kOperandASlotV1,
            alternate_root,
            alternate_closure, &why),
        why);
    BOOST_CHECK_MESSAGE(
        source::VerifyExternalProducerClosureV3(
            honest.shape, honest.bundle,
            source::kOperandASlotV1,
            honest_root, honest_closure, &why),
        why);
    BOOST_CHECK_MESSAGE(
        source::VerifyExternalProducerClosureV3(
            alternate.shape, alternate.bundle,
            source::kOperandASlotV1,
            alternate_root,
            alternate_closure, &why),
        why);

    // Both sides are independently valid under the same public shape.  A
    // producer/CTL subtree from the alternate computation cannot be paired
    // with the honest semantic leaf relation.
    BOOST_CHECK(
        !source::VerifyExternalProducerClosureV3(
            honest.shape, honest.bundle,
            source::kOperandASlotV1,
            alternate_root,
            alternate_closure, &why));

    // Transplant only a separately valid producer proof subtree.  Preserve the
    // honest outer transcript and claimed owning root so this is not rejected
    // by a host witness comparison.  The verifier must reject the alternate
    // proof's group-0 row commitment at the proof-owned R0 alias.
    auto cross_witness_attack = honest_closure;
    BOOST_REQUIRE(
        !cross_witness_attack.producer_children.empty());
    BOOST_REQUIRE(
        !alternate_closure.producer_children.empty());
    cross_witness_attack.producer_children[0].proof =
        alternate_closure.producer_children[0].proof;
    cross_witness_attack.producer_children[0].proof_commitment =
        alternate_closure.producer_children[0]
            .proof_commitment;
    why.clear();
    BOOST_CHECK(
        !source::VerifyExternalProducerClosureV3(
            honest.shape, honest.bundle,
            source::kOperandASlotV1,
            honest_root,
            cross_witness_attack, &why));
    BOOST_CHECK(
        why.find(
            "external_verify_producer_binding_0") !=
        std::string::npos);

    auto proof_attack = honest_closure;
    BOOST_REQUIRE(
        !proof_attack.producer_children.empty());
    BOOST_REQUIRE(
        !proof_attack.producer_children[0]
             .proof.batch.queries.empty());
    BOOST_REQUIRE(
        !proof_attack.producer_children[0]
             .proof.batch.queries[0]
             .group_rows.empty());
    BOOST_REQUIRE(
        !proof_attack.producer_children[0]
             .proof.batch.queries[0]
             .group_rows[0].values.empty());
    proof_attack.producer_children[0]
        .proof.batch.queries[0]
        .group_rows[0].values[0] =
        gf::Add(
            proof_attack.producer_children[0]
                .proof.batch.queries[0]
                .group_rows[0].values[0],
            gf::Fp3::One());
    BOOST_CHECK(
        !source::VerifyExternalProducerClosureV3(
            honest.shape, honest.bundle,
            source::kOperandASlotV1,
            honest_root, proof_attack, &why));
}

BOOST_AUTO_TEST_CASE(
    gemm_dot_safe_alg_r0_closes_A_and_B_without_sha_authority)
{
    const Fixture& fixture = SharedFixture();
    for (uint32_t slot :
         {source::kOperandASlotV1,
          source::kOperandBSlotV1}) {
        source::GemmDotExternalClosureV4 closure;
        std::string why;
        BOOST_REQUIRE_MESSAGE(
            source::ProveGemmDotExternalClosureV4(
                fixture.shape, fixture.spec,
                fixture.layer, fixture.extract,
                fixture.bundle, slot,
                closure, &why),
            why);
        BOOST_CHECK_MESSAGE(
            source::VerifyGemmDotExternalClosureV4(
                fixture.shape, fixture.bundle,
                slot, closure, &why),
            why);
        BOOST_CHECK(
            closure.all_r0_before_challenge);
        BOOST_CHECK(
            closure.exact_producer_coverage);
        BOOST_CHECK(
            closure.exact_consumer_coverage);
        BOOST_CHECK(
            closure.proof_owned_terminal_cancellation);
        BOOST_CHECK(
            !closure.producer_authority_commitment
                 .IsNull());
        BOOST_REQUIRE(
            !closure.producer_children.empty());
        for (const auto& child :
             closure.producer_children) {
            BOOST_REQUIRE_EQUAL(
                child.proof.batch.groups.size(),
                3U);
            BOOST_CHECK_EQUAL(
                child.proof.batch.groups[0]
                    .column_count,
                8U);
            BOOST_CHECK(
                rc::Fri3AlgDigestToUint256(
                    child.proof.batch.groups[0]
                        .row_commit.root) ==
                child.owning_r0_root);
        }
    }
}

BOOST_AUTO_TEST_CASE(
    gemm_dot_safe_alg_rejects_valid_alternate_r0_transplant)
{
    const Fixture honest = BuildFixture(2);
    const Fixture alternate = BuildFixture(-3);
    source::GemmDotExternalClosureV4 honest_closure;
    source::GemmDotExternalClosureV4 alternate_closure;
    std::string why;
    BOOST_REQUIRE_MESSAGE(
        source::ProveGemmDotExternalClosureV4(
            honest.shape, honest.spec,
            honest.layer, honest.extract,
            honest.bundle,
            source::kOperandASlotV1,
            honest_closure, &why),
        why);
    BOOST_REQUIRE_MESSAGE(
        source::ProveGemmDotExternalClosureV4(
            alternate.shape, alternate.spec,
            alternate.layer, alternate.extract,
            alternate.bundle,
            source::kOperandASlotV1,
            alternate_closure, &why),
        why);
    BOOST_REQUIRE_MESSAGE(
        source::VerifyGemmDotExternalClosureV4(
            honest.shape, honest.bundle,
            source::kOperandASlotV1,
            honest_closure, &why),
        why);
    BOOST_REQUIRE_MESSAGE(
        source::VerifyGemmDotExternalClosureV4(
            alternate.shape, alternate.bundle,
            source::kOperandASlotV1,
            alternate_closure, &why),
        why);

    auto attack = honest_closure;
    BOOST_REQUIRE(
        !attack.producer_children.empty());
    BOOST_REQUIRE(
        !alternate_closure
             .producer_children.empty());
    attack.producer_children[0].proof =
        alternate_closure
            .producer_children[0].proof;
    attack.producer_children[0]
        .proof_commitment =
        alternate_closure
            .producer_children[0]
            .proof_commitment;
    why.clear();
    BOOST_CHECK(
        !source::VerifyGemmDotExternalClosureV4(
            honest.shape, honest.bundle,
            source::kOperandASlotV1,
            attack, &why));
    BOOST_CHECK(
        why.find(
            "gemm_dot_v4_verify_producer_binding_0") !=
        std::string::npos);
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
    const auto& join =
        leaf.unified_same_parent_ctl_join;
    const auto input =
        source::BuildUnifiedSameParentCtlVerificationInputV2(
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
            .group_rows[1].values.size(),
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
        rc::kRCStage3EpisodeMemoryValue;
    receiver_value_attack.batch.queries[0]
        .group_rows[1]
        .values[receiver_value_column] =
        gf::Add(
            receiver_value_attack.batch.queries[0]
                .group_rows[1]
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
        !source::VerifyUnifiedSameParentCtlJoinV2(
            leaf.manifest, root_attack, &why));

    auto terminal_attack = join;
    terminal_attack
        .receiver_terminals[
            source::kOperandASlotV1]
        .alpha1_sum =
        gf::Add(
            terminal_attack
                .receiver_terminals[
                    source::kOperandASlotV1]
                .alpha1_sum,
            gf::Fp3::One());
    BOOST_CHECK(
        !source::VerifyUnifiedSameParentCtlJoinV2(
            leaf.manifest, terminal_attack, &why));
}

BOOST_AUTO_TEST_CASE(
    distinct_valid_witness_terminal_splice_rejects_in_unified_proof)
{
    const Fixture& honest = SharedFixture();
    const Fixture alternate = BuildFixture(-3);
    const auto& honest_leaf =
        honest.bundle.leaves.front();
    const auto& alternate_leaf =
        alternate.bundle.leaves.front();
    BOOST_REQUIRE(
        source::VerifyUnifiedSameParentCtlJoinV2(
            honest_leaf.manifest,
            honest_leaf.unified_same_parent_ctl_join));
    BOOST_REQUIRE(
        source::VerifyUnifiedSameParentCtlJoinV2(
            alternate_leaf.manifest,
            alternate_leaf
                .unified_same_parent_ctl_join));

    // This is the attack enabled by the former three-proof layout: keep A/Y
    // from one valid relation but import the B terminal from another valid
    // relation.  V2 has one proof and one R0, so changing either terminal
    // makes the verifier-owned constraint system disagree with that proof.
    auto spliced =
        honest_leaf.unified_same_parent_ctl_join;
    spliced.source_terminals[
        source::kOperandBSlotV1] =
        alternate_leaf
            .unified_same_parent_ctl_join
            .source_terminals[
                source::kOperandBSlotV1];
    spliced.receiver_terminals[
        source::kOperandBSlotV1] =
        alternate_leaf
            .unified_same_parent_ctl_join
            .receiver_terminals[
                source::kOperandBSlotV1];
    const auto input =
        source::BuildUnifiedSameParentCtlVerificationInputV2(
            honest_leaf.manifest, spliced);
    BOOST_REQUIRE_MESSAGE(input.valid, input.note);
    std::string why;
    BOOST_CHECK(
        !aq::AirQuotientVerifyRowsSplitRapSafeV2(
            input.expected_cs, *input.proof,
            input.expected_base_column_indices,
            input.public_fs_seed, &why));
    BOOST_CHECK(
        !source::VerifyUnifiedSameParentCtlJoinV2(
            honest_leaf.manifest,
            spliced, &why));

    auto proof_transplant =
        honest_leaf.unified_same_parent_ctl_join;
    proof_transplant.proof =
        alternate_leaf
            .unified_same_parent_ctl_join.proof;
    BOOST_CHECK(
        !source::VerifyUnifiedSameParentCtlJoinV2(
            honest_leaf.manifest,
            proof_transplant, &why));

    // Keep the complete unified proof from the honest witness but import the
    // independently valid ordinary Alg proof consumed by recursion.  The
    // unified R0 is exactly the ordinary proof's source-column trace tree,
    // so rewriting every public receipt field still cannot splice witnesses.
    auto main_proof_transplant = honest_leaf;
    main_proof_transplant.proof =
        alternate_leaf.proof;
    main_proof_transplant.canonical_proof_bytes =
        alternate_leaf.canonical_proof_bytes;
    main_proof_transplant.node_root =
        alternate_leaf.node_root;
    main_proof_transplant.proof_commitment =
        alternate_leaf.proof_commitment;
    main_proof_transplant.n_lde =
        alternate_leaf.n_lde;
    main_proof_transplant.receipt_commitment =
        source::ComputeLeafReceiptCommitmentV1(
            main_proof_transplant);
    BOOST_REQUIRE(
        !main_proof_transplant
             .receipt_commitment.IsNull());
    BOOST_CHECK(
        !source::VerifyLeafV1(
            honest_leaf.manifest.shape,
            honest_leaf.manifest.tile_begin,
            honest_leaf.manifest.tile_count,
            main_proof_transplant, &why));
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
