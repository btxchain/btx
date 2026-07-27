// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BTX_MATMUL_MATMUL_V4_RC_STAGE3_EPISODE_WIRING_BINDING_H
#define BTX_MATMUL_MATMUL_V4_RC_STAGE3_EPISODE_WIRING_BINDING_H

// ===========================================================================
// PR-89 relation endpoints #16/#17/#18 — EpisodeWiring{Transpose,Residual,
// RoundOrder}.  ONE construction, three instances.
//
// The wiring schedules are verifier-derived from the GEMM/Extract manifest
// (BuildRCStage3EpisodeWiring{Transpose,Residual,RoundOrder}Schedule) and every
// edge already carries an executable AirQuotientProof (dual-LogUp transpose with
// verifier-owned β/γ, residual add, round-order copy) plus a pin_commitment and
// registered source/y/residual/consumer roots.  What was missing is the LEDGER
// binding that ties the ordered edge set to a single endpoint proof_root.
//
// For each family this module folds  leaf_i = LeafHashRow([i, schedule
// canonical fields, pin_commitment lanes, registered roots, edge output
// alg-roots (transposed_vector_root ...)], i)  into an ordered proof_root.  The
// verifier RE-DERIVES the schedule from the manifest and requires leaf-for-leaf
// equality (schedule_index == i, edge.schedule == derived[i]) AND the recomputed
// proof_root == the committed endpoint proof_root.  Omission, reorder, and root
// substitution all fail closed.
//
// Multiset (permutation) error of the underlying dual-LogUp is ≤ O(N)/|Fp3| ≈
// 2^-170 per (β,γ); this ledger fold floor is 2^128 alg-hash.  Flips NO
// consensus/authority gate.
// ===========================================================================

#include <matmul/matmul_v4_rc_stage3_episode_wiring_product.h>
#include <matmul/matmul_v4_rc_stage3_gemm_extract.h>
#include <matmul/matmul_v4_rc_stage3_relation_closure.h>

#include <cstdint>
#include <string>

#include <uint256.h>

namespace matmul::v4::rc {

inline constexpr uint16_t kRCStage3EpisodeWiringBindingVersion = 1;

struct RCStage3WiringLedgerRoots {
    uint256 transpose_proof_root{};
    uint256 residual_proof_root{};
    uint256 round_order_proof_root{};
};

/** Prover-side: the three ordered edge-ledger proof roots. */
[[nodiscard]] RCStage3WiringLedgerRoots
ComputeRCStage3WiringLedgerRoots(const RCStage3EpisodeWiringProduct& product);

struct RCStage3WiringBindingResult {
    bool transpose_schedule_matches{false}; // derived == edge schedules, ordered
    bool transpose_fold_matches{false};     // recomputed proof_root == committed
    bool residual_schedule_matches{false};
    bool residual_fold_matches{false};
    bool round_order_schedule_matches{false};
    bool round_order_fold_matches{false};
    bool binding_complete{false};
    RCStage3WiringLedgerRoots roots;
    std::string note;
};

/**
 * Verifier-side: re-derive all three schedules from the manifest, require
 * leaf-for-leaf schedule equality, and require each recomputed ordered
 * proof_root to equal the committed endpoint proof_root.
 */
[[nodiscard]] bool VerifyRCStage3WiringLedgerBinding(
    const RCStage3GemmExtractManifest& manifest,
    const RCStage3EpisodeWiringProduct& product,
    const RCStage3WiringLedgerRoots& committed,
    RCStage3WiringBindingResult& out, std::string* why = nullptr);

/** Semantic pins the openings lane wires into the endpoint-16/17/18 slots. */
struct RCStage3WiringSemanticPin {
    bool transpose_complete{false};
    bool residual_complete{false};
    bool round_order_complete{false};
    RCStage3WiringLedgerRoots roots;
    std::string note;
};

[[nodiscard]] RCStage3WiringSemanticPin
RCStage3WiringWireSemanticPin(const RCStage3WiringBindingResult& result);

} // namespace matmul::v4::rc

#endif // BTX_MATMUL_MATMUL_V4_RC_STAGE3_EPISODE_WIRING_BINDING_H
