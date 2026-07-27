// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BTX_MATMUL_MATMUL_V4_RC_STAGE3_EPISODE_BUILDER_TRACE_BINDING_H
#define BTX_MATMUL_MATMUL_V4_RC_STAGE3_EPISODE_BUILDER_TRACE_BINDING_H

// ===========================================================================
// PR-89 relation endpoint #4 — EpisodeBuilderTrace (SHA-stream <-> field-vector
// junction).
//
// A hybrid BuilderTraceSchedule manifest.  The committed object is the
// canonical Lambda(params)-ordered leaf-tensor ledger
// (matmul_v4_rc_stage3_episode_builder_trace.h): trace_columns[] each carrying
// a wiring_vector_root, produced from the endpoint-3 XOF outputs through the
// dequant shard AIRs.  This module re-anchors that ledger to the Poseidon
// VectorRootAlg consensus authority (leaf_i = alg_hash::LeafHashRow(row_i, i),
// Compress fold) — SHA is transport-only.
//
// TWO-LAYER ALG FOLD:
//   * Expansion ledger  leaf_j = LeafHashRow([expansion_index, kind, round,
//       layer, rows, cols, xof_index_hash, source_link_root lanes,
//       shard output alg-roots...], j)               -> expansion_ledger_root
//   * Trace-column ledger leaf_i = LeafHashRow([trace_index, tensor, round,
//       layer, rows, cols, first_column, n_chunks, expansion_index,
//       wiring_vector_root lanes], i)                -> builder_trace_root
//
// CROSS-PIN at the junction: expansion.source_link_root == endpoint-3's §4
// stream_column_root as a 32-BYTE PUBLIC VALUE EQUALITY (a pin, NOT a cross-hash
// re-fold) — no collision coupling between the SHA and Poseidon domains.
//
// The verifier re-derives the entire schedule from the canonical
// Lambda(params) ordering deterministically and requires leaf-for-leaf
// equality: contiguous 0-based trace/expansion indices, every trace column
// referencing a live expansion, and the recomputed builder_trace_root equal to
// the committed alg root.  Each wiring_vector_root is the alg root the GEMM
// operand openings (endpoints 5/6) open — closing the
// operand-roots-registered-but-unproduced residual
// (matmul_v4_rc_stage3_episode_relation_product.h:30-38).
//
// Floors: 2^128 in both domains; the junction is exact 32-byte equality. Flips
// NO consensus/authority gate.
// ===========================================================================

#include <matmul/matmul_v4_rc_alg_hash.h>
#include <matmul/matmul_v4_rc_stage3_episode_builder_trace.h>
#include <matmul/matmul_v4_rc_stage3_relation_closure.h>

#include <cstdint>
#include <string>
#include <vector>

#include <uint256.h>

namespace matmul::v4::rc {

inline constexpr uint16_t kRCStage3BuilderTraceBindingVersion = 1;

struct RCStage3BuilderTraceAlgRoots {
    uint256 expansion_ledger_root{};
    uint256 builder_trace_root{};
    /** Ordered wiring_vector_root the GEMM operand openings (endpoints 5/6)
     *  open, one per canonical trace column. */
    std::vector<uint256> wiring_vector_roots;
};

/**
 * Prover-side: compute the two VectorRootAlg ledger roots and export the
 * ordered wiring_vector_roots.  Deterministic from the product alone.
 */
[[nodiscard]] RCStage3BuilderTraceAlgRoots
ComputeRCStage3BuilderTraceAlgRoots(
    const RCStage3EpisodeBuilderTraceProduct& product);

struct RCStage3BuilderTraceAlgBindingResult {
    RCStage3RelationEndpoint endpoint{
        RCStage3RelationEndpoint::EpisodeBuilderTrace};
    bool schedule_canonical_ordered{false}; // contiguous 0-based indices, live refs
    bool expansion_ledger_matches{false};   // recomputed == committed
    bool trace_ledger_matches{false};       // recomputed == committed
    bool cross_pin_ok{false};               // every source_link_root == ep3 stream root
    bool root_memory_consistent{false};     // builder_trace_root words == root_memory
    bool binding_complete{false};
    uint256 expansion_ledger_root{};
    uint256 builder_trace_root{};
    std::vector<uint256> wiring_vector_roots;
    std::string note;
};

/**
 * Verifier-side: re-derive the canonical schedule leaf-for-leaf, fold to the
 * alg roots, require equality to the committed alg roots, cross-pin every
 * expansion's source_link_root to the corresponding endpoint-3 §4
 * stream_column_root, and check the builder_trace_root words match root_memory.
 *
 * `committed_expansion_ledger_root` / `committed_builder_trace_root` are the
 * alg roots the openings lane pins into the product commitment.
 * `ep3_stream_column_roots` is indexed by expansion_index (junction equality).
 */
[[nodiscard]] bool VerifyRCStage3BuilderTraceAlgBinding(
    const RCStage3EpisodeBuilderTraceProduct& product,
    const uint256& committed_expansion_ledger_root,
    const uint256& committed_builder_trace_root,
    const std::vector<uint256>& ep3_stream_column_roots,
    RCStage3BuilderTraceAlgBindingResult& out,
    std::string* why = nullptr);

/**
 * Semantic pin the openings lane wires into the endpoint-4 registry slot.
 * `semantic_relation_complete` is true iff the alg binding verified with no
 * tamper.  `wiring_vector_roots` are handed to endpoints 5/6 as the operand
 * roots they must open against.
 */
struct RCStage3BuilderTraceSemanticPin {
    RCStage3RelationEndpoint endpoint{
        RCStage3RelationEndpoint::EpisodeBuilderTrace};
    bool semantic_relation_complete{false};
    uint256 builder_trace_root{};
    std::vector<uint256> wiring_vector_roots;
    std::string note;
};

[[nodiscard]] RCStage3BuilderTraceSemanticPin
RCStage3BuilderTraceWireSemanticPin(
    const RCStage3BuilderTraceAlgBindingResult& result);

} // namespace matmul::v4::rc

#endif // BTX_MATMUL_MATMUL_V4_RC_STAGE3_EPISODE_BUILDER_TRACE_BINDING_H
