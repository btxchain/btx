// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BTX_MATMUL_MATMUL_V4_RC_STAGE3_STREAM_ENDPOINT_H
#define BTX_MATMUL_MATMUL_V4_RC_STAGE3_STREAM_ENDPOINT_H

// ============================================================================
// PR-89 §4 stream / SHA256d endpoint closer as a composable fragment.
//
// The §4 manifest recursive bindings (stage3_hash_air::HashManifestRecursive-
// Binding and the Verify{XofCounter,ChaChaInitAndBlock,CompleteStream}Manifest
// family) fold an ordered committed-column stream into a SHA256d Merkle root
// (leaf i binds its stream index i) and then commit that root under the family
// domain.  Those are exposed ONLY as scalar boolean verifiers.  This unit
// exposes the SAME opening as an in-AIR, CS-verifiable closer with the identical
// shape role as BuildRCStage3OpeningConstraintSystem (the Poseidon alg_hash
// opening), but with SHA256d as the Merkle primitive, so the registry lane can
// assemble a role AIR C_rho for the roles that carry a §4 stream endpoint
// (XofCounter / ChaChaInitAndBlock / CompleteStream / DirectSha256d families).
//
// ARCHITECTURE — RECURSIVE-CHILD (see the .cpp header for the concrete cost
// model that rules out INLINE): the heavy SHA256d Merkle fold is a SEPARATE
// AirConstraintSystem child (RCStage3StreamEndpointClosure::child_cs), folded
// by the air_recurse aggregation seam; C_rho column-shifts only the LIGHT deg-1
// binding fragment (BuildRCStage3StreamEndpointConstraintSystem) that pins the
// committed root the child authenticates and exposes the aliasable value cell.
// Both are verified at the constraint-system level (CountWitnessViolationsOnH).
// ============================================================================

#include <matmul/matmul_v4_rc_air_quotient.h>
#include <matmul/matmul_v4_rc_gkr_field_ext3.h>

#include <uint256.h>

#include <array>
#include <cstdint>
#include <string>
#include <vector>

namespace matmul::v4::rc {

/** The §4 committed-stream families that carry a SHA256d endpoint. Values match
 * stage3_hash_air::GapCode for {Xof,ChaChaInitAndBlock,CompleteStream}Manifest;
 * DirectSha256d covers the CompleteStream DirectSha256dManifest overload. */
enum class RCStage3StreamFamily : uint8_t {
    XofCounter = 4,
    ChaChaInitAndBlock = 5,
    CompleteStream = 6,
    DirectSha256d = 7,
};

/** One endpoint opening: the private stream value authenticated at leaf_index
 * plus the SHA256d Merkle authentication path (one sibling + direction bit per
 * level).  leaf_index and its bits are PUBLIC (as in the reference opening);
 * stream_value and siblings are witness. */
struct RCStage3StreamEndpointManifest {
    uint32_t leaf_index{0};
    std::array<uint32_t, 8> stream_value{};
    std::vector<std::array<uint32_t, 8>> siblings; // one per level (== path_len)
    std::vector<bool> directions;                  // one per level (== index bits)
};

/**
 * Result of one §4 stream endpoint closure.
 *
 * (A) child_cs / child_witness : the genuine in-AIR SHA256d Merkle-path fold
 *     (leaf SHA256d, then one SHA256d compression per level, chained through the
 *     vertical boundary-link bus), with the terminal fold output pinned to
 *     committed_root.  CountWitnessViolationsOnH(child_cs, child_witness) == 0
 *     honest, > 0 under any stream-value / sibling / root tamper.
 * (B) bind_cs / bind_witness : the LIGHT deg-1 fragment C_rho column-shifts.
 *     It pins committed_root as public constants and exposes the aliasable value
 *     cell (bind_value_column) the registry aliases to the fragment kernel cell.
 */
struct RCStage3StreamEndpointClosure {
    bool ok{false};
    std::string note;
    RCStage3StreamFamily family{RCStage3StreamFamily::CompleteStream};
    uint32_t leaf_index{0};
    uint32_t path_len{0};
    /** The closer's canonical SHA256d Merkle root (== the last fold output). */
    std::array<uint32_t, 8> committed_root{};
    uint32_t child_semantic_compressions{0};

    air_quotient::AirConstraintSystem<gkr_field::Fp3> child_cs;
    std::vector<std::vector<gkr_field::Fp3>> child_witness;
    uint32_t child_output_export_base{0};
    uint32_t child_violations{0};

    air_quotient::AirConstraintSystem<gkr_field::Fp3> bind_cs;
    std::vector<std::vector<gkr_field::Fp3>> bind_witness;
    uint32_t bind_value_column{0};
    uint32_t bind_root_base{0};
    uint32_t bind_violations{0};
};

/** Width / aliasable-value column of the light binding fragment. */
inline constexpr uint32_t kRCStage3StreamEndpointBindWidth = 10;
inline constexpr uint32_t kRCStage3StreamEndpointBindValueColumn = 0;
inline constexpr uint32_t kRCStage3StreamEndpointBindRootBase = 2;

/** Deterministic honest manifest for one endpoint (canonical per-level siblings
 * seeded from family/leaf_index); reproduces a concrete opening for tests and
 * registry probes.  `path_len` levels; direction bits == index bits. */
[[nodiscard]] RCStage3StreamEndpointManifest
BuildRCStage3StreamEndpointCanonicalManifest(
    RCStage3StreamFamily family, const std::array<uint32_t, 8>& stream_value,
    uint32_t leaf_index, uint32_t path_len);

/**
 * Fast scalar SHA256d Merkle fold: leaf(domain ‖ index ‖ stream_value) folded
 * up the authentication path to the committed root, byte-identical to the root
 * the in-AIR child pins.  No AIR/commitment is built, so this is O(path_len)
 * SHA256d evaluations — used to exhibit the fold's value/sibling/index binding
 * without the heavy vertical child build.
 */
[[nodiscard]] bool RCStage3StreamEndpointCommittedRoot(
    RCStage3StreamFamily family,
    const RCStage3StreamEndpointManifest& manifest,
    std::array<uint32_t, 8>& out_root, std::string* why = nullptr);

/**
 * (Exposed helper the registry lane composes.)  Build the full §4 stream
 * endpoint closer: the recursive-child SHA256d Merkle fold (A) and the light
 * column-shiftable binding fragment (B).  `committed_root` is produced by the
 * fold and returned; a matching aggregation child pin must carry it.
 */
[[nodiscard]] RCStage3StreamEndpointClosure RCStage3StreamEndpointClose(
    RCStage3StreamFamily family,
    const RCStage3StreamEndpointManifest& manifest, const uint256& fs_seed,
    std::string* why = nullptr, bool run_cs_checks = true);

/**
 * (Column-shiftable CS the registry direct-products into C_rho.)  The light
 * deg-1 binding fragment for a fixed public leaf_index / committed_root /
 * path_len: value column (kRCStage3StreamEndpointBindValueColumn) is the
 * aliasable cell; the eight root columns are pinned to committed_root as public
 * constants; the SHA compute is deferred to the child from
 * RCStage3StreamEndpointClose.  n_rows == 2.
 */
[[nodiscard]] air_quotient::AirConstraintSystem<gkr_field::Fp3>
BuildRCStage3StreamEndpointConstraintSystem(
    RCStage3StreamFamily family, uint32_t leaf_index,
    const std::array<uint32_t, 8>& committed_root, uint32_t path_len);

/** Honest column-major witness for the light binding fragment above:
 * `ctl_value` is carried at the value column and the leaf-value alias column,
 * and committed_root fills the root columns. */
[[nodiscard]] std::vector<std::vector<gkr_field::Fp3>>
BuildRCStage3StreamEndpointWitness(
    const std::array<uint32_t, 8>& committed_root,
    const gkr_field::Fp3& ctl_value);

} // namespace matmul::v4::rc

#endif // BTX_MATMUL_MATMUL_V4_RC_STAGE3_STREAM_ENDPOINT_H
