// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BTX_MATMUL_MATMUL_V4_RC_STAGE3_EPISODE_BUILDER_TRACE_H
#define BTX_MATMUL_MATMUL_V4_RC_STAGE3_EPISODE_BUILDER_TRACE_H

#include <matmul/matmul_v4_rc_stage3_episode_builder_operand_xof.h>
#include <matmul/matmul_v4_rc_stage3_episode_relation_product.h>

#include <cstdint>
#include <string>
#include <vector>

namespace matmul::v4::rc {

inline constexpr uint16_t kRCStage3EpisodeBuilderTraceVersion = 1;

/**
 * One quotient shard for
 *
 *   out = signed(mu) * 2^scale, scale = e0 + 2*e1.
 *
 * The mu and repeated-scale roots are reconstructed from endpoint 3.  The
 * output root is therefore proof-derived and can be used directly as one
 * canonical flat-memory shard root.
 */
struct RCStage3EpisodeBuilderTraceAirShard {
    uint32_t shard_index{0};
    uint64_t value_begin{0};
    uint32_t logical_rows{0};
    uint32_t n_rows{0};
    uint256 mantissa_root{};
    uint256 repeated_scale_root{};
    uint256 scale_bit0_root{};
    uint256 scale_bit1_root{};
    uint256 scale_factor_root{};
    uint256 output_root{};
    air_quotient::AirQuotientProof<gkr_field::Fp3> proof;
};

/**
 * One unique expanded tensor. Datacenter X0 joins the verifier-ordered
 * row-block endpoint-3 instances into one complete X0 tensor.
 */
struct RCStage3EpisodeBuilderTraceExpansion {
    uint32_t expansion_index{0};
    RCStage3EpisodeOperandKind kind{};
    uint32_t round_index{0};
    uint32_t layer_index{0};
    bool episode_shared{false};
    uint32_t rows{0};
    uint32_t cols{0};
    std::vector<uint32_t> operand_xof_indices;
    uint256 source_link_root{};
    std::vector<RCStage3EpisodeBuilderTraceAirShard> shards;
    uint256 expansion_commitment{};
};

/**
 * One leaf tensor in verifier-derived Lambda(params). Intermediate
 * Extract/GEMM outputs are deliberately absent: they are produced by later
 * semantic endpoints. A shared endpoint-3 expansion may feed several
 * canonical trace tensors, each with its own column-identity-bound vector
 * root.
 */
struct RCStage3EpisodeBuilderTraceColumn {
    uint32_t trace_index{0};
    RCGkrTensor tensor{RCGkrTensor::Q};
    uint32_t round_index{0};
    uint32_t layer_index{0};
    uint32_t rows{0};
    uint32_t cols{0};
    uint32_t first_column{0};
    uint32_t n_chunks{0};
    uint32_t expansion_index{0};
    uint256 wiring_vector_root{};

    bool operator==(
        const RCStage3EpisodeBuilderTraceColumn&) const = default;
};

struct RCStage3EpisodeBuilderTraceProduct {
    uint16_t version{kRCStage3EpisodeBuilderTraceVersion};
    uint256 statement_commitment{};
    uint256 params_manifest_commitment{};
    uint256 seed_chain_product_commitment{};
    uint256 operand_xof_product_commitment{};
    uint256 layout_schedule_root{};
    std::vector<RCStage3EpisodeBuilderTraceExpansion> expansions;
    std::vector<RCStage3EpisodeBuilderTraceColumn> trace_columns;
    uint256 builder_trace_root{};
    /** Eight canonical 32-bit words of builder_trace_root. */
    RCStage3EpisodeSemanticMemoryBundle root_memory;
    uint256 product_commitment{};
};

/**
 * Proof-derived flat opening of one canonical leaf tensor.
 *
 * These values are reconstructed from the exact counter-XOF outputs already
 * committed by endpoint 3 and the dequantization schedule proved at endpoint
 * 4. They are the native-prover bridge into the corresponding GEMM A/B
 * witness; verifiers continue to consume only the committed vector roots.
 */
struct RCStage3EpisodeBuilderTraceLeafOpening {
    RCGkrTensor tensor{RCGkrTensor::Q};
    uint32_t round_index{0};
    uint32_t layer_index{0};
    uint32_t first_column{0};
    uint32_t n_chunks{0};
    std::vector<int8_t> values;
};

[[nodiscard]] uint256
ComputeRCStage3EpisodeBuilderTraceProductCommitment(
    const RCStage3EpisodeBuilderTraceProduct& product);

[[nodiscard]] bool
MaterializeRCStage3EpisodeBuilderTraceLeafOpenings(
    const RCStage3SuccinctProof& statement,
    const RCEpisodeParams& params,
    const RCStage3EpisodeBuilderParamsProduct& params_product,
    const RCStage3EpisodeBuilderSeedChainProduct& seed_chain,
    const RCStage3EpisodeBuilderOperandXofProduct& operand_xof,
    const RCStage3EpisodeBuilderTraceProduct& product,
    std::vector<RCStage3EpisodeBuilderTraceLeafOpening>& out,
    std::string* why = nullptr);

/**
 * Build and prove the local endpoint-4 relation from structurally canonical
 * endpoint-1..3 products. This does not execute the parent proofs; the full
 * Prove entry point below does.
 */
[[nodiscard]] bool BuildRCStage3EpisodeBuilderTraceProduct(
    const RCStage3SuccinctProof& statement,
    const RCEpisodeParams& params,
    const RCStage3EpisodeBuilderParamsProduct& params_product,
    const RCStage3EpisodeBuilderSeedChainProduct& seed_chain,
    const RCStage3EpisodeBuilderOperandXofProduct& operand_xof,
    RCStage3EpisodeBuilderTraceProduct& out,
    std::string* why = nullptr);

/** Execute endpoints 1-3, then build every endpoint-4 child proof. */
[[nodiscard]] bool ProveRCStage3EpisodeBuilderTraceProduct(
    const RCStage3SuccinctProof& statement,
    const RCEpisodeParams& params,
    const RCStage3EpisodeBuilderParamsProduct& params_product,
    const RCStage3EpisodeBuilderSeedChainProduct& seed_chain,
    const RCStage3EpisodeBuilderOperandXofProduct& operand_xof,
    RCStage3EpisodeBuilderTraceProduct& out,
    std::string* why = nullptr);

/** Exact schedule/root validation without executing quotient proofs. */
[[nodiscard]] bool ValidateRCStage3EpisodeBuilderTraceSchedule(
    const RCStage3SuccinctProof& statement,
    const RCEpisodeParams& params,
    const RCStage3EpisodeBuilderParamsProduct& params_product,
    const RCStage3EpisodeBuilderSeedChainProduct& seed_chain,
    const RCStage3EpisodeBuilderOperandXofProduct& operand_xof,
    const RCStage3EpisodeBuilderTraceProduct& product,
    std::string* why = nullptr);

/**
 * Execute endpoint 4 after structurally checking its parent products. This is
 * the recursive-composition seam: callers which have already executed the
 * parent children need not execute them twice.
 */
[[nodiscard]] bool VerifyRCStage3EpisodeBuilderTraceLocalProduct(
    const RCStage3SuccinctProof& statement,
    const RCEpisodeParams& params,
    const RCStage3EpisodeBuilderParamsProduct& params_product,
    const RCStage3EpisodeBuilderSeedChainProduct& seed_chain,
    const RCStage3EpisodeBuilderOperandXofProduct& operand_xof,
    const RCStage3EpisodeBuilderTraceProduct& product,
    std::string* why = nullptr);

/** Execute endpoints 1-3, every dequant quotient, and root memory. */
[[nodiscard]] bool VerifyRCStage3EpisodeBuilderTraceProduct(
    const RCStage3SuccinctProof& statement,
    const RCEpisodeParams& params,
    const RCStage3EpisodeBuilderParamsProduct& params_product,
    const RCStage3EpisodeBuilderSeedChainProduct& seed_chain,
    const RCStage3EpisodeBuilderOperandXofProduct& operand_xof,
    const RCStage3EpisodeBuilderTraceProduct& product,
    std::string* why = nullptr);

/**
 * Require every expanded leaf A/B use in a canonical GEMM/Extract manifest
 * to equal endpoint 4's proof-derived vector root. The same roots are then
 * consumed by the wiring-copy schedule.
 */
[[nodiscard]] bool VerifyRCStage3EpisodeBuilderTraceManifestBinding(
    const RCStage3SuccinctProof& statement,
    const RCEpisodeParams& params,
    const RCStage3EpisodeBuilderTraceProduct& product,
    const RCStage3GemmExtractManifest& manifest,
    std::string* why = nullptr);

struct RCStage3EpisodeBuilderTraceAudit {
    RCStage3RelationEndpoint endpoint{
        RCStage3RelationEndpoint::EpisodeBuilderTrace};
    bool verifier_derived_layout_schedule{false};
    bool exact_endpoint_1_3_composition{false};
    bool all_dequant_children_executable{false};
    bool every_generated_source_linked{false};
    bool gemm_wiring_manifest_binding_executable{false};
    bool canonical_trace_root_memory_executable{false};
    bool bounded_local_relation_complete{false};
    bool endpoint1_ancestor_complete{false};
    bool endpoint2_ancestor_complete{false};
    bool endpoint3_ancestor_complete{false};
    bool producer_provenance_complete{false};
    bool semantic_complete{false};
    bool production_streaming_complete{false};
    bool recursively_consumed{false};
    std::string remaining;
};

[[nodiscard]] RCStage3EpisodeBuilderTraceAudit
CurrentRCStage3EpisodeBuilderTraceAudit(
    bool endpoint1_ancestor_complete,
    bool endpoint2_ancestor_complete,
    bool endpoint3_ancestor_complete);

inline constexpr bool
    kRCStage3EpisodeBuilderTraceBoundedLocalExecutable = true;
inline constexpr bool
    kRCStage3EpisodeBuilderTraceProductionStreamingComplete = false;
inline constexpr bool
    kRCStage3EpisodeBuilderTraceRecursivelyConsumed = false;

} // namespace matmul::v4::rc

#endif // BTX_MATMUL_MATMUL_V4_RC_STAGE3_EPISODE_BUILDER_TRACE_H
