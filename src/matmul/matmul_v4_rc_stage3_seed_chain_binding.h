// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BTX_MATMUL_MATMUL_V4_RC_STAGE3_SEED_CHAIN_BINDING_H
#define BTX_MATMUL_MATMUL_V4_RC_STAGE3_SEED_CHAIN_BINDING_H

// ===========================================================================
// PR-89 relation endpoint #2 — EpisodeBuilderSeedChain (§4 SHA256d clone).
//
// The consensus round-seed derivation is a chain of one SHA-256 pass per round
// (RCStage3EpisodeBuilderSeedChainProduct.steps, round-major).  Each step maps
// to an ordered SHA compression boundary instance stream.  This module adds the
// §4 recursive binding over that per-round stream under a NEW family_domain
// "DirectSha256dSeedChain": leaf i binds round index i (order-binding), the
// stream folds to `stream_column_root`, and (product_commitment ||
// stream_column_root || round_count) commits to one binding value.
//
// It additionally verifies the seed CHAIN edges the product enforces: round 0's
// external source is σ (from the header commitment), and round r's external
// source is the proof-owned round root r-1.  A broken edge, a reordered round,
// or a tampered seed all change the recomputed binding / edge check and fail
// closed.  The verifier re-derives the stream from the typed per-round SHA
// manifests — never a native replay.
//
// Floor: 2^128 SHA256d.  Flips NO consensus/authority gate.
// ===========================================================================

#include <matmul/matmul_v4_rc_stage3_episode_builder_seed_chain.h>
#include <matmul/matmul_v4_rc_stage3_hash_air.h>
#include <matmul/matmul_v4_rc_stage3_relation_closure.h>

#include <cstdint>
#include <string>

#include <uint256.h>

namespace matmul::v4::rc {

inline constexpr uint16_t kRCStage3SeedChainBindingVersion = 1;

/** New §4 family domain separator for the per-round seed boundary stream. */
inline constexpr char kRCStage3SeedChainFamilyDomain[] =
    "DirectSha256dSeedChain";

struct RCStage3SeedChainAlgBinding {
    stage3_hash_air::HashManifestRecursiveBinding binding;
    uint256 manifest_commitment{}; // == product_commitment
    uint64_t round_count{0};
};

/**
 * Prover-side: derive the ordered per-round SHA boundary stream from the typed
 * seed-chain product and build the §4 recursive binding over it.  Each round is
 * one single-block SHA pass, so the stream is exactly one boundary per round.
 */
[[nodiscard]] bool ComputeRCStage3SeedChainAlgBinding(
    const RCStage3EpisodeBuilderSeedChainProduct& product,
    RCStage3SeedChainAlgBinding& out, std::string* why = nullptr);

struct RCStage3SeedChainBindingResult {
    RCStage3RelationEndpoint endpoint{
        RCStage3RelationEndpoint::EpisodeBuilderSeedChain};
    bool boundary_stream_derived{false}; // steps -> ordered per-round stream
    bool round_index_ordered{false};     // step[r].round_index == r
    bool binding_verified{false};        // §4 VerifyHashManifestRecursiveBinding
    bool chain_edges_ok{false};          // σ / round-root chain edges hold
    bool binding_complete{false};
    uint256 stream_column_root{};
    uint64_t round_count{0};
    std::string note;
};

/**
 * Verifier-side: re-derive the per-round boundary stream, re-run the §4 binding
 * against the committed binding, require contiguous round indices, and enforce
 * the σ / round-root chain edges.  `statement.public_inputs.sigma` anchors round
 * 0; product.round_root_manifest.round_roots anchor the rest.
 */
[[nodiscard]] bool VerifyRCStage3SeedChainAlgBinding(
    const RCStage3SuccinctProof& statement,
    const RCStage3EpisodeBuilderSeedChainProduct& product,
    const RCStage3SeedChainAlgBinding& committed,
    RCStage3SeedChainBindingResult& out, std::string* why = nullptr);

/** Semantic pin the openings lane wires into the endpoint-2 registry slot. */
struct RCStage3SeedChainSemanticPin {
    RCStage3RelationEndpoint endpoint{
        RCStage3RelationEndpoint::EpisodeBuilderSeedChain};
    bool semantic_relation_complete{false};
    uint256 stream_column_root{};
    std::string note;
};

[[nodiscard]] RCStage3SeedChainSemanticPin
RCStage3SeedChainWireSemanticPin(const RCStage3SeedChainBindingResult& result);

} // namespace matmul::v4::rc

#endif // BTX_MATMUL_MATMUL_V4_RC_STAGE3_SEED_CHAIN_BINDING_H
