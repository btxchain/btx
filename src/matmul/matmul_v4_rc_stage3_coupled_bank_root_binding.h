// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BTX_MATMUL_MATMUL_V4_RC_STAGE3_COUPLED_BANK_ROOT_BINDING_H
#define BTX_MATMUL_MATMUL_V4_RC_STAGE3_COUPLED_BANK_ROOT_BINDING_H

// ===========================================================================
// PR-89 relation endpoint #29 — CoupledBankRoot (§4 SHA256d manifest clone).
//
// The coupled bank digest is a fixed-program SHA256d over (tag || page_bytes).
// BuildRCStage3CoupledBankRootManifest maps the bank to an ordered stream of
// SHA compression boundary instances (BuildShaManifestBoundaryInstances) — the
// committed columns the fixed-program provenance AIR consumes.  This module
// adds the missing §4 recursive binding: it folds that ordered boundary-column
// stream into a Merkle `stream_column_root` (leaf i binds compression/page
// index i) under a NEW family_domain "DirectSha256dCoupledBankRoot", commits
// (manifest_commitment || stream_column_root || instance_count) into one
// binding value, and pins the manifest's public `bank_root`.
//
// Because the leaf index is folded into the preimage and the manifest
// commitment is folded into the binding value, a wrong page byte, a page
// reorder, a substituted stream root, or a wrong instance_count changes the
// recomputed binding and the §4 verify fails closed.  The verifier re-derives
// the boundary stream from the typed manifest.sha256d (never a native replay)
// and re-runs the §4 binding, requiring exact equality.
//
// Floor: 2^128 SHA256d.  Flips NO consensus/authority gate.
// ===========================================================================

#include <matmul/matmul_v4_rc_stage3_coupled_missing_relations.h>
#include <matmul/matmul_v4_rc_stage3_hash_air.h>
#include <matmul/matmul_v4_rc_stage3_relation_closure.h>

#include <cstdint>
#include <string>

#include <uint256.h>

namespace matmul::v4::rc {

inline constexpr uint16_t kRCStage3CoupledBankRootBindingVersion = 1;

/** New §4 family domain separator for the bank-root boundary stream. */
inline constexpr char kRCStage3CoupledBankRootFamilyDomain[] =
    "DirectSha256dCoupledBankRoot";

struct RCStage3CoupledBankRootAlgBinding {
    stage3_hash_air::HashManifestRecursiveBinding binding;
    uint256 manifest_commitment{};
    uint256 bank_root{};
    uint64_t instance_count{0};
};

/**
 * Prover-side: derive the SHA compression boundary stream from the typed bank
 * manifest and build the §4 recursive binding over it, pinning bank_root.
 * Deterministic from the manifest alone.
 */
[[nodiscard]] bool ComputeRCStage3CoupledBankRootAlgBinding(
    const RCStage3CoupledBankRootManifest& manifest,
    RCStage3CoupledBankRootAlgBinding& out,
    std::string* why = nullptr);

struct RCStage3CoupledBankRootBindingResult {
    RCStage3RelationEndpoint endpoint{
        RCStage3RelationEndpoint::CoupledBankRoot};
    bool boundary_stream_derived{false}; // manifest.sha256d -> ordered stream
    bool binding_verified{false};        // §4 VerifyHashManifestRecursiveBinding
    bool instance_count_ok{false};       // binding count == derived stream length
    bool bank_root_pinned{false};        // committed bank_root == manifest.bank_root
    bool binding_complete{false};
    uint256 stream_column_root{};
    uint256 bank_root{};
    uint64_t instance_count{0};
    std::string note;
};

/**
 * Verifier-side: re-derive the boundary stream from the typed manifest, re-run
 * the §4 binding, require exact equality to the committed binding, check the
 * instance count matches the derived stream length, and pin bank_root.
 */
[[nodiscard]] bool VerifyRCStage3CoupledBankRootAlgBinding(
    const RCStage3CoupledBankRootManifest& manifest,
    const RCStage3CoupledBankRootAlgBinding& committed,
    const uint256& committed_bank_root,
    RCStage3CoupledBankRootBindingResult& out,
    std::string* why = nullptr);

/** Semantic pin the openings lane wires into the endpoint-29 registry slot. */
struct RCStage3CoupledBankRootSemanticPin {
    RCStage3RelationEndpoint endpoint{
        RCStage3RelationEndpoint::CoupledBankRoot};
    bool semantic_relation_complete{false};
    uint256 stream_column_root{};
    uint256 bank_root{};
    std::string note;
};

[[nodiscard]] RCStage3CoupledBankRootSemanticPin
RCStage3CoupledBankRootWireSemanticPin(
    const RCStage3CoupledBankRootBindingResult& result);

} // namespace matmul::v4::rc

#endif // BTX_MATMUL_MATMUL_V4_RC_STAGE3_COUPLED_BANK_ROOT_BINDING_H
