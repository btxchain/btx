// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BTX_MATMUL_MATMUL_V4_RC_STAGE3_EPISODE_BUILDER_OPERAND_XOF_H
#define BTX_MATMUL_MATMUL_V4_RC_STAGE3_EPISODE_BUILDER_OPERAND_XOF_H

#include <matmul/matmul_v4_rc_stage3_episode_builder_seed_chain.h>

#include <cstdint>
#include <string>
#include <vector>

namespace matmul::v4::rc {

inline constexpr uint16_t
    kRCStage3EpisodeBuilderOperandXofVersion = 1;

enum class RCStage3EpisodeOperandKind : uint8_t {
    Q = 1,
    K = 2,
    V = 3,
    X0 = 4,
    WUp = 5,
    WDown = 6,
};

struct RCStage3EpisodeOperandSeedDerivation {
    stage3_hash_air::ShaManifest sha;
    stage3_hash_semantic::FlatBoundaryProofBundle proof;
};

/** One unique consensus ExpandMxDequantInt8 stream. */
struct RCStage3EpisodeOperandXofInstance {
    uint64_t schedule_index{0};
    RCStage3EpisodeOperandKind kind{};
    uint32_t round_index{0};
    uint32_t layer_index{0};
    uint32_t row_block{0};
    bool episode_shared{false};
    uint32_t rows{0};
    uint32_t cols{0};
    uint256 source{};
    /** One derivation normally; datacenter X0 row blocks have two. */
    std::vector<RCStage3EpisodeOperandSeedDerivation> seed_derivations;
    stage3_hash_air::CounterXofManifest mantissa;
    stage3_hash_semantic::FlatBoundaryProofBundle mantissa_proof;
    stage3_hash_air::CounterXofManifest scale;
    stage3_hash_semantic::FlatBoundaryProofBundle scale_proof;
};

struct RCStage3EpisodeBuilderOperandXofProduct {
    uint16_t version{kRCStage3EpisodeBuilderOperandXofVersion};
    uint256 statement_commitment{};
    uint256 params_commitment{};
    uint256 seed_chain_product_commitment{};
    uint64_t output_cells{0};
    std::vector<RCStage3EpisodeOperandXofInstance> instances;
    RCStage3EpisodeSemanticMemoryBundle output_memory;
    uint256 product_commitment{};
};

[[nodiscard]] uint256
ComputeRCStage3EpisodeBuilderOperandXofProductCommitment(
    const RCStage3EpisodeBuilderOperandXofProduct& product);

/** Native prover-side manifest construction; no proof execution. */
[[nodiscard]] bool BuildRCStage3EpisodeBuilderOperandXofProduct(
    const RCStage3SuccinctProof& statement,
    const RCEpisodeParams& params,
    const RCStage3EpisodeBuilderSeedChainProduct& seed_chain,
    RCStage3EpisodeBuilderOperandXofProduct& out,
    std::string* why = nullptr);

/** Fill every derivation/XOF AIR and every semantic-memory shard proof. */
[[nodiscard]] bool ProveRCStage3EpisodeBuilderOperandXofProduct(
    const RCStage3SuccinctProof& statement,
    const RCEpisodeParams& params,
    const RCStage3EpisodeBuilderSeedChainProduct& seed_chain,
    RCStage3EpisodeBuilderOperandXofProduct& out,
    std::string* why = nullptr);

/** Structural exact-inventory check used by adversarial schedule tests. */
[[nodiscard]] bool ValidateRCStage3EpisodeBuilderOperandXofSchedule(
    const RCStage3SuccinctProof& statement,
    const RCEpisodeParams& params,
    const RCStage3EpisodeBuilderSeedChainProduct& seed_chain,
    const RCStage3EpisodeBuilderOperandXofProduct& product,
    std::string* why = nullptr);

[[nodiscard]] bool VerifyRCStage3EpisodeBuilderOperandXofProduct(
    const RCStage3SuccinctProof& statement,
    const RCEpisodeParams& params,
    const RCStage3EpisodeBuilderSeedChainProduct& seed_chain,
    const RCStage3EpisodeBuilderOperandXofProduct& product,
    std::string* why = nullptr);

struct RCStage3EpisodeBuilderOperandXofAudit {
    RCStage3RelationEndpoint endpoint{
        RCStage3RelationEndpoint::EpisodeBuilderOperandXof};
    bool exact_unique_operand_schedule{false};
    bool seed_derivation_sha_executable{false};
    bool all_counter_xof_children_executable{false};
    bool chacha_required_by_consensus{false};
    bool output_memory_equality_executable{false};
    bool local_relation_complete{false};
    bool endpoint1_ancestor_complete{false};
    bool endpoint2_ancestor_complete{false};
    bool producer_provenance_complete{false};
    bool semantic_complete{false};
    bool production_streaming_manifest_complete{false};
    bool recursively_consumed{false};
    std::string remaining;
};

[[nodiscard]] RCStage3EpisodeBuilderOperandXofAudit
CurrentRCStage3EpisodeBuilderOperandXofAudit(
    bool endpoint1_ancestor_complete,
    bool endpoint2_ancestor_complete);

inline constexpr bool
    kRCStage3EpisodeBuilderOperandXofLocalProductExecutable = true;
inline constexpr bool
    kRCStage3EpisodeBuilderOperandXofProductionStreamingComplete = false;

} // namespace matmul::v4::rc

#endif
