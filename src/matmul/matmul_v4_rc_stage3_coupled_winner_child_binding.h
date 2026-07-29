// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BTX_MATMUL_MATMUL_V4_RC_STAGE3_COUPLED_WINNER_CHILD_BINDING_H
#define BTX_MATMUL_MATMUL_V4_RC_STAGE3_COUPLED_WINNER_CHILD_BINDING_H

#include <matmul/matmul_v4_rc_stage3_bounded_semantic_composition.h>
#include <matmul/matmul_v4_rc_stage3_coupled_winner_capture.h>

#include <cstdint>
#include <string>

class CBlockHeader;

namespace matmul::v4::rc {

inline constexpr uint16_t
    kRCStage3CoupledWinnerChildBindingVersionV2 = 2;
// Source-ABI name retained while the normalized parent migrates.  There is no
// V1 wire compatibility: newly built bindings are V2 only.
inline constexpr uint16_t
    kRCStage3CoupledWinnerChildBindingVersionV1 =
        kRCStage3CoupledWinnerChildBindingVersionV2;

/**
 * Proof-owned equality product between the winner reseal and the complete
 * bounded coupled child family.
 *
 * This object is deliberately not a readiness receipt.  It can be produced
 * only after every typed child proof has executed and every raw child opening
 * has been equality-checked against the canonical winner-capture roots.
 * Production still needs to replace the bounded children with their
 * recursively compressed equivalents before this product is wire-sized.
 */
struct RCStage3CoupledWinnerChildBindingV1 {
    uint16_t version{
        kRCStage3CoupledWinnerChildBindingVersionV1};
    uint256 finalized_header_hash{};
    uint256 statement_commitment{};
    uint256 coupled_shape_commitment{};
    uint256 winner_receipt_commitment{};

    uint64_t scheduled_page_instances{0};
    uint64_t accumulation_links{0};
    uint64_t stage_boundary_links{0};
    uint64_t barrier_links{0};

    uint256 initial_state_binding{};
    uint256 scheduled_page_binding{};
    uint256 accumulation_binding{};
    uint256 stage_boundary_binding{};
    uint256 bank_hash_binding{};
    uint256 barrier_digest_binding{};
    /**
     * Equality binding for the six bounded cells copied into the no-replay
     * parent.  Each cell is checked against its executed GEMM/bank/Extract
     * child opening before this commitment can be formed.
     */
    uint256 representative_cell_binding{};
    uint256 child_proof_family_binding{};
    uint256 product_commitment{};

    bool operator==(
        const RCStage3CoupledWinnerChildBindingV1&) const = default;
};

[[nodiscard]] uint256
CommitRCStage3CoupledWinnerChildBindingV1(
    const RCStage3CoupledWinnerChildBindingV1& binding);

/**
 * Execute all bounded coupled proof children and bind their exact openings to
 * the winner receipt.
 *
 * Verification performs no coupled oracle replay and accepts no host
 * completion bit.  In particular it:
 *
 *  - executes Bank, initial-state, GEMM, signed-range, exchange/permutation,
 *    Mix, Extract, bank-root SHA and barrier/digest SHA proof families;
 *  - recomputes every capture A/B/Y and multi-page accumulation root from the
 *    proof-owned child openings;
 *  - recomputes every permutation/Mix/material/Extract boundary root from the
 *    proof-owned stage vectors; and
 *  - requires the bank root, all barrier roots and the coupled digest to be
 *    the terminals of the executed root-chain proofs.
 *
 * The bounded composition carries flat openings, so this closes the semantic
 * handoff but not production recursive compression.
 */
[[nodiscard]] bool
VerifyRCStage3CoupledWinnerChildBindingV1(
    const CBlockHeader& finalized_header,
    int32_t height,
    const RCCoupParams& params,
    const RCCoupOptions& options,
    const RCStage3SuccinctProof& statement,
    const RCStage3CoupledWinnerReceiptV1& winner,
    const RCStage3BoundedCoupledSemanticComposition& children,
    RCStage3CoupledWinnerChildBindingV1& out,
    std::string* why = nullptr);

inline constexpr bool
    kRCStage3CoupledWinnerChildBindingExecutableV1 = true;
inline constexpr bool
    kRCStage3CoupledWinnerChildBindingRecursivelyCompressedV1 = false;
inline constexpr bool
    kRCStage3CoupledWinnerChildBindingAuthorityReadyV1 = false;

static_assert(kRCStage3CoupledWinnerChildBindingExecutableV1);
static_assert(
    !kRCStage3CoupledWinnerChildBindingRecursivelyCompressedV1);
static_assert(
    !kRCStage3CoupledWinnerChildBindingAuthorityReadyV1);

} // namespace matmul::v4::rc

#endif // BTX_MATMUL_MATMUL_V4_RC_STAGE3_COUPLED_WINNER_CHILD_BINDING_H
