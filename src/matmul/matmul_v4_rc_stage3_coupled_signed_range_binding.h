// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BTX_MATMUL_MATMUL_V4_RC_STAGE3_COUPLED_SIGNED_RANGE_BINDING_H
#define BTX_MATMUL_MATMUL_V4_RC_STAGE3_COUPLED_SIGNED_RANGE_BINDING_H

// ===========================================================================
// PR-89 relation endpoint #33 — CoupledGemmSignedRange (endpoint-9 clone).
//
// The coupled GEMM outputs are range-proved by the executable signed-range AIR
// (BuildRCStage3SignedRangeColumns builds the 69 committed columns; the
// kRCStage3RangeValue column commits the signed values with an EXACT 31-bit
// decomposition — no probabilistic gap).  Each shard exports a RANGE_VALUE
// column root.  This module adds the ledger binding that made
// EpisodeGemmSignedRange natively complete:
//
//   * an ORDERED Poseidon alg fold  leaf_s = LeafHashRow([s, cell_begin,
//     logical_rows, max_abs, RANGE_VALUE root lanes, Y interval root lanes], s)
//     -> value_roots_commitment (order-binding: leaf carries the shard index);
//   * per-shard EQUALITY  RANGE_VALUE root == CoupledGemmOutputY interval root
//     (same re-anchored alg tree -> root identity).
//
// A wrong range value (changes the committed RANGE_VALUE root), a reordered
// shard (changes the ordered fold), or a mismatched Y interval root all fail
// closed.  Range soundness itself is discharged by the separate executable
// VerifyRCStage3CoupledSignedRangeExecution (AirQuotientVerify per shard); this
// binding closes the value-roots ledger + Y root-identity link.
//
// Floor: 2^128 alg-hash on the fold; range check is exact (31-bit).  Flips NO
// consensus/authority gate.
// ===========================================================================

#include <matmul/matmul_v4_rc_alg_hash.h>
#include <matmul/matmul_v4_rc_stage3_gemm_extract.h>
#include <matmul/matmul_v4_rc_stage3_relation_closure.h>

#include <cstdint>
#include <string>
#include <vector>

#include <uint256.h>

namespace matmul::v4::rc {

inline constexpr uint16_t kRCStage3CoupledSignedRangeBindingVersion = 1;

/** One shard entry: a real signed-range pin (with its RANGE_VALUE column root
 * filled by the executable column builder) plus the registered
 * CoupledGemmOutputY interval root the RANGE_VALUE root must equal. */
struct RCStage3SignedRangeShardEntry {
    RCStage3SignedRangePin pin;
    uint256 y_interval_root{};
};

/** Ordered alg fold over the shard entries: order-binding value-roots ledger. */
[[nodiscard]] uint256 ComputeRCStage3SignedRangeLedgerFold(
    const std::vector<RCStage3SignedRangeShardEntry>& entries);

struct RCStage3SignedRangeAlgBinding {
    uint256 value_roots_commitment{}; // ordered alg fold over the shards
    uint32_t shard_count{0};
};

[[nodiscard]] bool ComputeRCStage3SignedRangeAlgBinding(
    const std::vector<RCStage3SignedRangeShardEntry>& entries,
    RCStage3SignedRangeAlgBinding& out, std::string* why = nullptr);

struct RCStage3SignedRangeBindingResult {
    RCStage3RelationEndpoint endpoint{
        RCStage3RelationEndpoint::CoupledGemmSignedRange};
    bool shards_ordered{false};        // pin.shard_index == s, contiguous, roots present
    bool value_roots_pinned{false};    // recomputed fold == committed
    bool y_interval_equal{false};      // RANGE_VALUE root == Y interval root per shard
    bool binding_complete{false};
    uint256 value_roots_commitment{};
    uint32_t shard_count{0};
    std::string note;
};

/**
 * Verifier-side: require contiguous shard indices, recompute the ordered fold
 * and require equality to the committed value_roots_commitment, and check every
 * shard's RANGE_VALUE root equals its registered CoupledGemmOutputY interval
 * root.
 */
[[nodiscard]] bool VerifyRCStage3SignedRangeAlgBinding(
    const std::vector<RCStage3SignedRangeShardEntry>& entries,
    const RCStage3SignedRangeAlgBinding& committed,
    RCStage3SignedRangeBindingResult& out, std::string* why = nullptr);

/** Semantic pin the openings lane wires into the endpoint-33 registry slot. */
struct RCStage3SignedRangeSemanticPin {
    RCStage3RelationEndpoint endpoint{
        RCStage3RelationEndpoint::CoupledGemmSignedRange};
    bool semantic_relation_complete{false};
    uint256 value_roots_commitment{};
    std::string note;
};

[[nodiscard]] RCStage3SignedRangeSemanticPin
RCStage3SignedRangeWireSemanticPin(
    const RCStage3SignedRangeBindingResult& result);

} // namespace matmul::v4::rc

#endif // BTX_MATMUL_MATMUL_V4_RC_STAGE3_COUPLED_SIGNED_RANGE_BINDING_H
