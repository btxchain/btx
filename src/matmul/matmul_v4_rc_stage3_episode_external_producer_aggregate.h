// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BTX_MATMUL_MATMUL_V4_RC_STAGE3_EPISODE_EXTERNAL_PRODUCER_AGGREGATE_H
#define BTX_MATMUL_MATMUL_V4_RC_STAGE3_EPISODE_EXTERNAL_PRODUCER_AGGREGATE_H

#include <matmul/matmul_v4_rc_stage3_episode_semantic_source_alg.h>

#include <cstdint>
#include <string>

namespace matmul::v4::rc::episode_external_producer_aggregate {

namespace source = episode_semantic_source_alg;

inline constexpr uint16_t kVersionV1 = 1;

/**
 * Complete proof-owned A/B ingress for one episode GEMM layer.
 *
 * The two ExternalProducer closures prove equality between the canonical
 * producer vectors and every sharded semantic-leaf A/B cell.  The two
 * GemmDot closures independently execute the SAFE GEMM relation and cancel
 * its A/B terminals against those same leaf cells.  The expected vector
 * roots remain verifier inputs: a receipt-carried root is never allowed to
 * declare its own upstream authority.
 *
 * This object deliberately stops before claiming that the expected roots are
 * equality-constrained to the corresponding builder/previous-Extract role
 * outputs in the normalized parent.  `role_export_equality_constrained` and
 * all authority flags therefore remain false until that final same-parent
 * attachment is executable.
 */
struct LayerClosureV1 {
    uint16_t version{kVersionV1};
    uint32_t layer_ordinal{0};
    source::LayerShapeV1 shape;
    uint32_t consumer_leaf_begin{0};
    uint32_t consumer_leaf_count{0};
    uint256 consumer_exact_coverage_commitment{};
    uint256 consumer_bundle_commitment{};
    uint256 operand_a_vector_root_alg{};
    uint256 operand_b_vector_root_alg{};
    source::ExternalProducerClosureV3 operand_a_external;
    source::ExternalProducerClosureV3 operand_b_external;
    source::GemmDotExternalClosureV4 operand_a_gemm;
    source::GemmDotExternalClosureV4 operand_b_gemm;
    uint256 closure_commitment{};
    bool exact_projection_set{false};
    bool all_children_proof_verified{false};
    bool all_r0_before_challenge{false};
    bool exact_producer_coverage{false};
    bool exact_consumer_coverage{false};
    bool proof_owned_terminal_cancellation{false};
    bool role_export_equality_constrained{false};
    bool recursive_child_consumed{false};
    bool semantic_closure{false};
    bool production_authority{false};
};

[[nodiscard]] bool ProveLayerClosureV1(
    const source::LayerShapeV1& shape,
    const RCStage3GemmExtractLayerManifest& spec,
    const RCStage3EpisodeGemmLayerProduct& layer,
    const RCStage3EpisodeExtractProduct& extract,
    uint64_t extract_tile_begin,
    const source::LayerBundleV1& consumer_bundle,
    uint32_t consumer_leaf_begin,
    LayerClosureV1& out,
    std::string* why = nullptr);

/**
 * Proof-only verification.  No native A/B/Y/Extract vectors are accepted.
 * The expected roots must come from the verifier-owned production relation
 * statement; verification rebuilds every child CS and replays all four
 * Split-RAP/FRI proofs.
 */
[[nodiscard]] bool VerifyLayerClosureV1(
    const source::LayerShapeV1& expected_shape,
    const source::LayerBundleV1& expected_consumer_bundle,
    uint32_t expected_consumer_leaf_begin,
    const uint256& expected_operand_a_vector_root_alg,
    const uint256& expected_operand_b_vector_root_alg,
    const LayerClosureV1& closure,
    std::string* why = nullptr);

} // namespace matmul::v4::rc::episode_external_producer_aggregate

#endif // BTX_MATMUL_MATMUL_V4_RC_STAGE3_EPISODE_EXTERNAL_PRODUCER_AGGREGATE_H
