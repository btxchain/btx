// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BTX_MATMUL_MATMUL_V4_RC_STAGE3_COUPLED_GEMM_RANGE_CTL_V3_H
#define BTX_MATMUL_MATMUL_V4_RC_STAGE3_COUPLED_GEMM_RANGE_CTL_V3_H

#include <matmul/matmul_v4_rc_stage3_coupled_gemm_product.h>
#include <matmul/matmul_v4_rc_stage3_coupled_missing_relations.h>
#include <matmul/matmul_v4_rc_stage3_gated_ctl_alias.h>
#include <matmul/matmul_v4_rc_stage3_recursive_hierarchy.h>

#include <array>
#include <cstdint>
#include <memory>
#include <string>
#include <vector>

namespace matmul::v4::rc::coupled_gemm_range_ctl_v3 {

namespace aq = air_quotient;
namespace gf = gkr_field;

inline constexpr uint16_t kVersionV3 = 3;
inline constexpr uint32_t kBusIdV3 = 0x47595233U; // "GYR3"

struct GemmChildV3 {
    uint64_t global_tile_ordinal{0};
    uint64_t schedule_index{0};
    uint64_t output_tile_index{0};
    RCStage3CoupledGemmDotPin dot_pin;
    uint256 base_row_commitment{};
    RCStage3CtlTerminal terminal;
    uint256 proof_commitment{};
    aq::AirQuotientSplitRapRowsProof proof;
};

struct RangeChildV3 {
    RCStage3SignedRangePin pin;
    uint256 base_row_commitment{};
    RCStage3CtlTerminal terminal;
    uint256 proof_commitment{};
    aq::AirQuotientSplitRapRowsProof proof;
};

struct ShardProofV3 {
    uint32_t shard_index{0};
    uint64_t cell_begin{0};
    uint32_t logical_rows{0};
    RCStage3CtlManifest manifest;
    RCStage3CtlChallenges challenges;
    RCStage3CtlChildPin gemm_role;
    RCStage3CtlChildPin range_role;
    std::vector<GemmChildV3> gemm_children;
    RangeChildV3 range_child;
    uint256 shard_commitment{};
    bool terminal_sum_zero{false};
};

struct ProductV3 {
    uint16_t version{kVersionV3};
    uint256 statement_commitment{};
    uint256 shape_commitment{};
    uint256 gemm_schedule_commitment{};
    uint256 range_manifest_commitment{};
    uint64_t expected_gemms{0};
    uint64_t expected_output_tiles{0};
    uint64_t expected_output_cells{0};
    std::vector<ShardProofV3> shards;
    uint256 product_commitment{};
    bool every_cell_partitioned{false};
    bool every_child_proof_verified{false};
    bool every_terminal_sum_zero{false};
    bool normalized_parent_consumed{false};
    bool production_authority{false};
};

/**
 * One of the two proof-owned role receipts exported by each shard.
 *
 * The GEMM role retains one native Split-RAP child per canonical output tile.
 * The range role retains the one native Split-RAP child for the complete
 * shard receiver.  `nodes` are not boolean summaries: each node retains the
 * canonical proof bytes, independently reconstructed constraint system,
 * exact R0 column schedule and public Fiat-Shamir seed used by the native
 * verifier.
 */
struct ParentRoleReceiptV3 {
    RCStage3RelationRole role{RCStage3RelationRole::CoupledGemm};
    uint32_t bus_id{0};
    recursive_hierarchy::ShardOrdinalManifestV1 manifest;
    std::vector<
        recursive_hierarchy::RetainedSplitRapHierarchyNodeV2> nodes;
    uint256 trace_commitment{};
    uint256 auxiliary_commitment{};
    uint256 challenge_commitment{};
    RCStage3CtlTerminal terminal;
    uint256 receipt_commitment{};
    bool exact_child_coverage{false};
    bool every_native_child_verified{false};
    bool dual_fp3_terminal_exported{false};
};

struct ParentShardReceiptsV3 {
    uint32_t shard_index{0};
    std::array<ParentRoleReceiptV3, 2> role;
    uint256 receipt_pair_commitment{};
    bool exact_role_order{false};
    bool dual_fp3_terminal_cancellation{false};
};

struct ParentReceiptBundleV3 {
    uint16_t version{kVersionV3};
    uint256 product_commitment{};
    std::vector<ParentShardReceiptsV3> shards;
    uint256 bundle_commitment{};
    bool every_split_rap_child_verified{false};
    bool every_dual_fp3_terminal_exported{false};
    bool every_shard_terminal_cancelled{false};
    /**
     * This bundle is the executable input to the normalized-parent lane.
     * It remains false until that lane has proved and re-entered the parent.
     */
    bool normalized_parent_consumed{false};
};

/**
 * Complete all-cell endpoint-33 proof.
 *
 * Every canonical GEMM tile contributes its END-selected Y cells to exactly
 * one shard bus.  The receiver is the shard's signed-range VALUE relation
 * selected by ACTIVE.  The prover may retain/revisit openings; the verifier
 * receives no native matrices and performs no GEMM replay.
 */
[[nodiscard]] bool ProveV3(
    const RCStage3SuccinctProof& statement,
    const RCStage3CoupledShape& shape,
    const std::vector<RCStage3CoupledGemmOpening>& openings,
    ProductV3& out,
    std::string* why = nullptr);

/**
 * Single-execution all-cell V3 prover.
 *
 * Each canonical GEMM callback is consumed synchronously.  The prover commits
 * every dot-product tile and the matching signed-range shard before releasing
 * the borrowed A/B/Y buffers.  Until both role R0 roots for a shard exist it
 * retains only authenticated polynomial sessions; the dual-Fp3 CTL challenge
 * is then derived and the SAFE-V13 child proofs are completed from those
 * committed coefficients.  No native application witness is retained and no
 * GEMM or episode is replayed.
 */
class StreamingProverV3 final {
public:
    StreamingProverV3(
        const RCStage3SuccinctProof& statement,
        const RCStage3CoupledShape& shape);
    ~StreamingProverV3();
    StreamingProverV3(StreamingProverV3&&) noexcept;
    StreamingProverV3& operator=(StreamingProverV3&&) noexcept;
    StreamingProverV3(const StreamingProverV3&) = delete;
    StreamingProverV3& operator=(const StreamingProverV3&) = delete;

    void OnGemm(const RCCoupGemmProofWitnessView& view);
    [[nodiscard]] bool Complete(std::string* why = nullptr) const;
    [[nodiscard]] bool Finalize(
        ProductV3& out,
        std::string* why = nullptr);
    [[nodiscard]] uint64_t RetainedNativeBytes() const;
    [[nodiscard]] uint64_t PeakRetainedNativeBytes() const;
    /** Exact vector payload retained for R0 polynomials/trees/traces. */
    [[nodiscard]] uint64_t RetainedProverBytes() const;
    [[nodiscard]] uint64_t PeakRetainedProverBytes() const;

private:
    class Impl;
    std::unique_ptr<Impl> impl_;
};

/** Proof-only verification; no opening/native-Y parameter exists. */
[[nodiscard]] bool VerifyV3(
    const RCStage3SuccinctProof& statement,
    const RCStage3CoupledShape& shape,
    const ProductV3& proof,
    std::string* why = nullptr);

[[nodiscard]] uint256 CommitProductV3(const ProductV3& proof);

/**
 * Reconstruct and natively verify every retained Split-RAP child before
 * exporting the two exact role receipts and dual-Fp3 terminals per shard.
 *
 * This is deliberately stronger than comparing proof or receipt roots on the
 * host.  Every node is accepted by AirQuotientVerifyRowsSplitRapSafeV2 against
 * a verifier-reconstructed CS, R0 schedule and FS seed.
 */
[[nodiscard]] bool BuildVerifiedParentReceiptsV3(
    const RCStage3SuccinctProof& statement,
    const RCStage3CoupledShape& shape,
    const ProductV3& proof,
    ParentReceiptBundleV3& out,
    std::string* why = nullptr);

[[nodiscard]] bool ValidateParentReceiptsV3(
    const RCStage3SuccinctProof& statement,
    const RCStage3CoupledShape& shape,
    const ProductV3& proof,
    const ParentReceiptBundleV3& receipts,
    std::string* why = nullptr);

} // namespace matmul::v4::rc::coupled_gemm_range_ctl_v3

#endif
