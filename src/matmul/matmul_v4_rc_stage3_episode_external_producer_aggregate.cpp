// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <matmul/matmul_v4_rc_stage3_episode_external_producer_aggregate.h>

#include <hash.h>

#include <limits>
#include <vector>

namespace matmul::v4::rc::episode_external_producer_aggregate {
namespace {

namespace gf = gkr_field;

bool Fail(std::string* why, const std::string& detail)
{
    if (why != nullptr) {
        *why =
            "stage3:episode_external_producer_aggregate:" +
            detail;
    }
    return false;
}

template <typename T>
std::vector<gf::Fp3> ToField(
    const std::vector<T>& values)
{
    std::vector<gf::Fp3> out;
    out.reserve(values.size());
    for (T value : values) {
        out.push_back(gf::FromSigned3(
            static_cast<int64_t>(value)));
    }
    return out;
}

uint256 CommitLayerClosureV1(
    const LayerClosureV1& closure)
{
    if (closure.version != kVersionV1 ||
        closure.shape.shape_commitment.IsNull() ||
        closure.operand_a_vector_root_alg.IsNull() ||
        closure.operand_b_vector_root_alg.IsNull() ||
        closure.output_y_vector_root_alg.IsNull() ||
        closure.operand_a_external
            .closure_commitment.IsNull() ||
        closure.operand_b_external
            .closure_commitment.IsNull() ||
        closure.output_y_external
            .closure_commitment.IsNull() ||
        closure.operand_a_gemm
            .closure_commitment.IsNull() ||
        closure.operand_b_gemm
            .closure_commitment.IsNull()) {
        return {};
    }
    HashWriter hash;
    hash << std::string{
                "BTX_RC_STAGE3_EPISODE_EXTERNAL_PRODUCER_AGGREGATE_V1"}
         << closure.version
         << closure.layer_ordinal
         << closure.shape.shape_commitment
         << closure.consumer_leaf_begin
         << closure.consumer_leaf_count
         << closure.consumer_exact_coverage_commitment
         << closure.consumer_bundle_commitment
         << closure.operand_a_vector_root_alg
         << closure.operand_b_vector_root_alg
         << closure.output_y_vector_root_alg
         << closure.operand_a_external.closure_commitment
         << closure.operand_b_external.closure_commitment
         << closure.output_y_external.closure_commitment
         << closure.operand_a_gemm.closure_commitment
         << closure.operand_b_gemm.closure_commitment
         << closure.exact_projection_set
         << closure.all_children_proof_verified
         << closure.all_r0_before_challenge
         << closure.exact_producer_coverage
         << closure.exact_consumer_coverage
         << closure.proof_owned_terminal_cancellation
         << closure.role_export_equality_constrained
         << closure.recursive_child_consumed
         << closure.semantic_closure
         << closure.production_authority;
    return hash.GetSHA256();
}

bool LocalClosureFlags(
    const source::ExternalProducerClosureV3& closure)
{
    return closure.all_r0_before_challenge &&
        closure.exact_producer_coverage &&
        closure.exact_consumer_coverage &&
        closure.proof_owned_terminal_cancellation;
}

bool LocalClosureFlags(
    const source::GemmDotExternalClosureV4& closure)
{
    return closure.all_r0_before_challenge &&
        closure.exact_producer_coverage &&
        closure.exact_consumer_coverage &&
        closure.proof_owned_terminal_cancellation;
}

} // namespace

bool ProveLayerClosureV1(
    const source::LayerShapeV1& shape,
    const RCStage3GemmExtractLayerManifest& spec,
    const RCStage3EpisodeGemmLayerProduct& layer,
    const RCStage3EpisodeExtractProduct& extract,
    uint64_t extract_tile_begin,
    const source::LayerBundleV1& consumer_bundle,
    uint32_t consumer_leaf_begin,
    LayerClosureV1& out,
    std::string* why)
{
    out = {};
    if (shape.shape_commitment.IsNull() ||
        shape.layer_ordinal != spec.ordinal ||
        layer.layer_ordinal != spec.ordinal ||
        consumer_bundle.shape != shape ||
        consumer_bundle.leaves.empty() ||
        consumer_bundle.leaves.size() >
            std::numeric_limits<uint32_t>::max() ||
        consumer_bundle
            .exact_coverage_commitment.IsNull() ||
        consumer_bundle.bundle_commitment.IsNull() ||
        layer.operand_a.empty() ||
        layer.operand_b.empty()) {
        return Fail(why, "prove_statement");
    }
    out.layer_ordinal = shape.layer_ordinal;
    out.shape = shape;
    out.consumer_leaf_begin = consumer_leaf_begin;
    out.consumer_leaf_count =
        static_cast<uint32_t>(
            consumer_bundle.leaves.size());
    out.consumer_exact_coverage_commitment =
        consumer_bundle.exact_coverage_commitment;
    out.consumer_bundle_commitment =
        consumer_bundle.bundle_commitment;
    out.operand_a_vector_root_alg =
        RCStage3VectorRootAlgCommitment(
            ToField(layer.operand_a));
    out.operand_b_vector_root_alg =
        RCStage3VectorRootAlgCommitment(
            ToField(layer.operand_b));
    out.output_y_vector_root_alg =
        RCStage3VectorRootAlgCommitment(
            ToField(layer.gemm_y));
    std::string child_why;
    if (out.operand_a_vector_root_alg.IsNull() ||
        out.operand_b_vector_root_alg.IsNull() ||
        out.output_y_vector_root_alg.IsNull() ||
        !source::ProveExternalProducerClosureV3(
            shape, layer, extract,
            extract_tile_begin, consumer_bundle,
            source::kOperandASlotV1,
            out.operand_a_vector_root_alg,
            out.operand_a_external, &child_why)) {
        return Fail(
            why, "prove_operand_a_external:" +
                child_why);
    }
    if (!source::ProveExternalProducerClosureV3(
            shape, layer, extract,
            extract_tile_begin, consumer_bundle,
            source::kOperandBSlotV1,
            out.operand_b_vector_root_alg,
            out.operand_b_external, &child_why)) {
        return Fail(
            why, "prove_operand_b_external:" +
                child_why);
    }
    if (!source::ProveExternalProducerClosureV3(
            shape, layer, extract,
            extract_tile_begin, consumer_bundle,
            source::kOutputYSlotV1,
            out.output_y_vector_root_alg,
            out.output_y_external, &child_why)) {
        return Fail(
            why, "prove_output_y_external:" +
                child_why);
    }
    if (!source::ProveGemmDotExternalClosureV4(
            shape, spec, layer, extract,
            consumer_bundle,
            source::kOperandASlotV1,
            out.operand_a_gemm, &child_why)) {
        return Fail(
            why, "prove_operand_a_gemm:" +
                child_why);
    }
    if (!source::ProveGemmDotExternalClosureV4(
            shape, spec, layer, extract,
            consumer_bundle,
            source::kOperandBSlotV1,
            out.operand_b_gemm, &child_why)) {
        return Fail(
            why, "prove_operand_b_gemm:" +
                child_why);
    }

    out.exact_projection_set =
        out.operand_a_external.projection_slot ==
            source::kOperandASlotV1 &&
        out.operand_b_external.projection_slot ==
            source::kOperandBSlotV1 &&
        out.output_y_external.projection_slot ==
            source::kOutputYSlotV1 &&
        out.operand_a_gemm.projection_slot ==
            source::kOperandASlotV1 &&
        out.operand_b_gemm.projection_slot ==
            source::kOperandBSlotV1;
    out.all_children_proof_verified = true;
    out.all_r0_before_challenge =
        out.operand_a_external
            .all_r0_before_challenge &&
        out.operand_b_external
            .all_r0_before_challenge &&
        out.output_y_external
            .all_r0_before_challenge &&
        out.operand_a_gemm
            .all_r0_before_challenge &&
        out.operand_b_gemm
            .all_r0_before_challenge;
    out.exact_producer_coverage =
        out.operand_a_external
            .exact_producer_coverage &&
        out.operand_b_external
            .exact_producer_coverage &&
        out.output_y_external
            .exact_producer_coverage &&
        out.operand_a_gemm
            .exact_producer_coverage &&
        out.operand_b_gemm
            .exact_producer_coverage;
    out.exact_consumer_coverage =
        out.operand_a_external
            .exact_consumer_coverage &&
        out.operand_b_external
            .exact_consumer_coverage &&
        out.output_y_external
            .exact_consumer_coverage &&
        out.operand_a_gemm
            .exact_consumer_coverage &&
        out.operand_b_gemm
            .exact_consumer_coverage;
    out.proof_owned_terminal_cancellation =
        out.operand_a_external
            .proof_owned_terminal_cancellation &&
        out.operand_b_external
            .proof_owned_terminal_cancellation &&
        out.output_y_external
            .proof_owned_terminal_cancellation &&
        out.operand_a_gemm
            .proof_owned_terminal_cancellation &&
        out.operand_b_gemm
            .proof_owned_terminal_cancellation;
    out.role_export_equality_constrained = false;
    out.recursive_child_consumed = false;
    out.semantic_closure = false;
    out.production_authority = false;
    out.closure_commitment =
        CommitLayerClosureV1(out);
    if (!out.exact_projection_set ||
        !out.all_children_proof_verified ||
        !out.all_r0_before_challenge ||
        !out.exact_producer_coverage ||
        !out.exact_consumer_coverage ||
        !out.proof_owned_terminal_cancellation ||
        out.closure_commitment.IsNull()) {
        return Fail(why, "prove_local_closure");
    }
    if (!VerifyLayerClosureV1(
            shape, consumer_bundle,
            consumer_leaf_begin,
            out.operand_a_vector_root_alg,
            out.operand_b_vector_root_alg,
            out.output_y_vector_root_alg,
            out, why)) {
        out = {};
        return false;
    }
    return true;
}

bool VerifyLayerClosureV1(
    const source::LayerShapeV1& expected_shape,
    const source::LayerBundleV1& expected_consumer_bundle,
    uint32_t expected_consumer_leaf_begin,
    const uint256& expected_operand_a_vector_root_alg,
    const uint256& expected_operand_b_vector_root_alg,
    const uint256& expected_output_y_vector_root_alg,
    const LayerClosureV1& closure,
    std::string* why)
{
    if (closure.version != kVersionV1 ||
        closure.layer_ordinal !=
            expected_shape.layer_ordinal ||
        closure.shape != expected_shape ||
        closure.consumer_leaf_begin !=
            expected_consumer_leaf_begin ||
        closure.consumer_leaf_count !=
            expected_consumer_bundle.leaves.size() ||
        closure.consumer_exact_coverage_commitment !=
            expected_consumer_bundle
                .exact_coverage_commitment ||
        closure.consumer_bundle_commitment !=
            expected_consumer_bundle.bundle_commitment ||
        closure.operand_a_vector_root_alg !=
            expected_operand_a_vector_root_alg ||
        closure.operand_b_vector_root_alg !=
            expected_operand_b_vector_root_alg ||
        closure.output_y_vector_root_alg !=
            expected_output_y_vector_root_alg ||
        closure.role_export_equality_constrained ||
        closure.recursive_child_consumed ||
        closure.semantic_closure ||
        closure.production_authority) {
        return Fail(why, "verify_statement");
    }
    std::string child_why;
    if (!source::VerifyExternalProducerClosureV3(
            expected_shape,
            expected_consumer_bundle,
            source::kOperandASlotV1,
            expected_operand_a_vector_root_alg,
            closure.operand_a_external,
            &child_why)) {
        return Fail(
            why, "verify_operand_a_external:" +
                child_why);
    }
    if (!source::VerifyExternalProducerClosureV3(
            expected_shape,
            expected_consumer_bundle,
            source::kOutputYSlotV1,
            expected_output_y_vector_root_alg,
            closure.output_y_external,
            &child_why)) {
        return Fail(
            why, "verify_output_y_external:" +
                child_why);
    }
    if (!source::VerifyExternalProducerClosureV3(
            expected_shape,
            expected_consumer_bundle,
            source::kOperandBSlotV1,
            expected_operand_b_vector_root_alg,
            closure.operand_b_external,
            &child_why)) {
        return Fail(
            why, "verify_operand_b_external:" +
                child_why);
    }
    if (!source::VerifyGemmDotExternalClosureV4(
            expected_shape,
            expected_consumer_bundle,
            source::kOperandASlotV1,
            closure.operand_a_gemm,
            &child_why)) {
        return Fail(
            why, "verify_operand_a_gemm:" +
                child_why);
    }
    if (!source::VerifyGemmDotExternalClosureV4(
            expected_shape,
            expected_consumer_bundle,
            source::kOperandBSlotV1,
            closure.operand_b_gemm,
            &child_why)) {
        return Fail(
            why, "verify_operand_b_gemm:" +
                child_why);
    }

    const bool exact_projection_set =
        closure.operand_a_external.projection_slot ==
            source::kOperandASlotV1 &&
        closure.operand_b_external.projection_slot ==
            source::kOperandBSlotV1 &&
        closure.output_y_external.projection_slot ==
            source::kOutputYSlotV1 &&
        closure.operand_a_gemm.projection_slot ==
            source::kOperandASlotV1 &&
        closure.operand_b_gemm.projection_slot ==
            source::kOperandBSlotV1;
    const bool all_r0_before_challenge =
        LocalClosureFlags(
            closure.operand_a_external) &&
        LocalClosureFlags(
            closure.operand_b_external) &&
        LocalClosureFlags(
            closure.output_y_external) &&
        LocalClosureFlags(
            closure.operand_a_gemm) &&
        LocalClosureFlags(
            closure.operand_b_gemm);
    if (!exact_projection_set ||
        !all_r0_before_challenge ||
        !closure.exact_projection_set ||
        !closure.all_children_proof_verified ||
        !closure.all_r0_before_challenge ||
        !closure.exact_producer_coverage ||
        !closure.exact_consumer_coverage ||
        !closure.proof_owned_terminal_cancellation ||
        closure.closure_commitment !=
            CommitLayerClosureV1(closure)) {
        return Fail(why, "verify_local_closure");
    }
    if (why != nullptr) {
        *why =
            "stage3:episode_external_producer_aggregate:"
            "all_five_layer_ingress_children_verified;"
            "normalized_role_export_alias_open";
    }
    return true;
}

} // namespace matmul::v4::rc::episode_external_producer_aggregate
