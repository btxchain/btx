// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BTX_MATMUL_MATMUL_V4_RC_STAGE3_EPISODE_BUILDER_SEED_CHAIN_H
#define BTX_MATMUL_MATMUL_V4_RC_STAGE3_EPISODE_BUILDER_SEED_CHAIN_H

#include <matmul/matmul_v4_rc_stage3_episode_builder_params.h>
#include <matmul/matmul_v4_rc_stage3_episode_round_roots.h>

#include <cstdint>
#include <string>
#include <vector>

namespace matmul::v4::rc {

inline constexpr uint16_t
    kRCStage3EpisodeBuilderSeedChainVersion = 1;

/** One verifier-ordered consensus round-seed derivation. */
struct RCStage3EpisodeBuilderSeedStep {
    uint32_t round_index{0};
    /** sigma for round zero; the preceding proof-owned round root otherwise. */
    uint256 source{};
    /** Consensus uses one SHA-256 pass for BTX_RC_ROUND_V1. */
    stage3_hash_air::ShaManifest sha;
    stage3_hash_semantic::FlatBoundaryProofBundle hash_proof;
};

/**
 * Exact endpoint-2 product.
 *
 * Every SHA compression is executed by the fixed-program provenance AIR.
 * `seed_memory` contains, in round-major order, the eight final SHA state
 * words for each derived seed.  The verifier recomputes its root from the
 * typed SHA boundaries and requires exact equality with the proof-owned
 * endpoint-2 VALUE/EXPORT column.
 */
struct RCStage3EpisodeBuilderSeedChainProduct {
    uint16_t version{kRCStage3EpisodeBuilderSeedChainVersion};
    uint256 statement_commitment{};
    uint256 header_commitment{};
    uint256 params_commitment{};
    uint256 sigma{};
    uint32_t expected_rounds{0};
    stage3_hash_air::EpisodeDigestManifest round_root_manifest;
    RCStage3EpisodeBuilderParamsProduct params_product;
    RCStage3RootChainVectorPin round_roots_pin;
    RCStage3RootChainVectorProof round_roots_proof;
    std::vector<RCStage3EpisodeBuilderSeedStep> steps;
    RCStage3EpisodeSemanticMemoryManifest seed_memory_manifest;
    RCStage3EpisodeSemanticMemoryProof seed_memory_proof;
    uint256 product_commitment{};
};

[[nodiscard]] uint256
ComputeRCStage3EpisodeBuilderSeedChainProductCommitment(
    const RCStage3EpisodeBuilderSeedChainProduct& product);

/**
 * Prover helper. Native SHA is used only to build witnesses/manifests; the
 * verifier below accepts exclusively through the fixed-program proofs.
 */
[[nodiscard]] bool ProveRCStage3EpisodeBuilderSeedChainProduct(
    const RCStage3SuccinctProof& statement,
    const RCEpisodeParams& expected_params,
    const stage3_hash_air::EpisodeDigestManifest& round_root_manifest,
    RCStage3EpisodeBuilderSeedChainProduct& out,
    std::string* why = nullptr);

[[nodiscard]] bool VerifyRCStage3EpisodeBuilderSeedChainProduct(
    const RCStage3SuccinctProof& statement,
    const RCEpisodeParams& expected_params,
    const RCStage3EpisodeBuilderSeedChainProduct& product,
    std::string* why = nullptr);

struct RCStage3EpisodeBuilderSeedChainAudit {
    RCStage3RelationEndpoint endpoint{
        RCStage3RelationEndpoint::EpisodeBuilderSeedChain};
    bool verifier_ordered_schedule{false};
    bool exact_all_instance_sha_execution{false};
    bool final_seed_words_memory_link{false};
    bool endpoint1_params_product_executed{false};
    bool round_root_vector_executed{false};
    bool local_relation_complete{false};
    bool public_consensus_ancestor_complete{false};
    bool endpoint1_ancestor_complete{false};
    bool round_root_ancestor_complete{false};
    bool producer_provenance_complete{false};
    bool semantic_complete{false};
    bool recursively_consumed{false};
    std::string remaining;
};

/**
 * Transitive audit. The three arguments are facts supplied by the unified
 * graph, not verifier switches: producer completion is true only when the
 * public consensus binding, endpoint 1, and round-root producer ancestors
 * are all already closed.
 */
[[nodiscard]] RCStage3EpisodeBuilderSeedChainAudit
CurrentRCStage3EpisodeBuilderSeedChainAudit(
    bool public_consensus_ancestor_complete,
    bool endpoint1_ancestor_complete,
    bool round_root_ancestor_complete);

inline constexpr bool
    kRCStage3EpisodeBuilderSeedChainLocalProductExecutable = true;
inline constexpr bool
    kRCStage3EpisodeBuilderSeedChainRecursivelyConsumed = false;

} // namespace matmul::v4::rc

#endif // BTX_MATMUL_MATMUL_V4_RC_STAGE3_EPISODE_BUILDER_SEED_CHAIN_H
