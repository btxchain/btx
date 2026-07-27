// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BTX_MATMUL_MATMUL_V4_RC_STAGE3_EPISODE_HEADER_TARGET_H
#define BTX_MATMUL_MATMUL_V4_RC_STAGE3_EPISODE_HEADER_TARGET_H

#include <matmul/matmul_v4_rc_stage3_episode.h>
#include <matmul/matmul_v4_rc_stage3_episode_semantic.h>
#include <matmul/matmul_v4_rc_stage3_constraint_bytecode.h>

#include <cstdint>
#include <string>

namespace matmul::v4::rc {

inline constexpr uint16_t kRCStage3EpisodeHeaderTargetVersion = 1;
inline constexpr uint32_t kRCStage3EpisodeHeaderTargetRows = 32;
inline constexpr uint32_t kRCStage3EpisodeHeaderTargetPublicCells = 68;

enum RCStage3EpisodeHeaderTargetColumn : uint32_t {
    kRCStage3EpisodeHeaderTargetByte = 0,
    kRCStage3EpisodeHeaderTargetExpectedByte,
    kRCStage3EpisodeHeaderTargetColumns,
};

struct RCStage3EpisodeHeaderTargetPin {
    uint16_t version{kRCStage3EpisodeHeaderTargetVersion};
    uint256 statement_commitment{};
    uint256 header_commitment{};
    uint32_t n_bits{0};
    uint256 target{};
    uint256 pin_commitment{};

    bool operator==(const RCStage3EpisodeHeaderTargetPin&) const = default;
};

struct RCStage3EpisodeHeaderTargetProduct {
    uint16_t version{kRCStage3EpisodeHeaderTargetVersion};
    RCStage3EpisodeHeaderTargetPin pin;
    air_quotient::AirQuotientProof<gkr_field::Fp3> compact_target_proof;
    RCStage3EpisodeSemanticMemoryManifest public_memory_manifest;
    RCStage3EpisodeSemanticMemoryProof public_memory_proof;
};

[[nodiscard]] bool BuildRCStage3EpisodeHeaderTargetPin(
    const RCStage3SuccinctProof& statement,
    RCStage3EpisodeHeaderTargetPin& out,
    std::string* why = nullptr);

[[nodiscard]] bool BuildRCStage3EpisodeHeaderTargetConstraintSystem(
    const RCStage3EpisodeHeaderTargetPin& pin,
    air_quotient::AirConstraintSystem<gkr_field::Fp3>& out,
    std::string* why = nullptr);
[[nodiscard]] uint256 ComputeRCStage3EpisodeHeaderTargetSeed(
    const RCStage3EpisodeHeaderTargetPin& pin);

/** Canonical recursive-interpreter form of compact-byte equality. */
[[nodiscard]] bool BuildRCStage3EpisodeHeaderTargetConstraintProgram(
    const RCStage3EpisodeHeaderTargetPin& pin,
    constraint_bytecode::Program& out,
    std::string* why = nullptr);

[[nodiscard]] bool BuildRCStage3EpisodeHeaderTargetProgramTable(
    const RCStage3EpisodeHeaderTargetPin& pin,
    constraint_bytecode::ProgramTable& out,
    std::string* why = nullptr);

[[nodiscard]] bool ProveRCStage3EpisodeHeaderTargetProduct(
    const RCStage3SuccinctProof& statement,
    RCStage3EpisodeHeaderTargetProduct& out,
    std::string* why = nullptr);

/**
 * `expected_*` are consensus-resolved public inputs. The caller must first
 * run the ordinary Stage-3 consensus binding against the actual header.
 */
[[nodiscard]] bool VerifyRCStage3EpisodeHeaderTargetProduct(
    const RCStage3SuccinctProof& statement,
    const uint256& expected_header_commitment,
    uint32_t expected_n_bits,
    const uint256& expected_target,
    const RCStage3EpisodeHeaderTargetProduct& product,
    std::string* why = nullptr);

struct RCStage3EpisodeHeaderTargetAudit {
    RCStage3RelationEndpoint endpoint{
        RCStage3RelationEndpoint::EpisodeDigestHeaderTarget};
    bool consensus_public_inputs_required{false};
    bool compact_target_relation_executable{false};
    bool exact_public_vector_proved{false};
    bool local_relation_complete{false};
    bool producer_provenance_complete{false};
    bool semantic_complete{false};
    bool recursively_consumed{false};
    std::string remaining;
};

[[nodiscard]] RCStage3EpisodeHeaderTargetAudit
CurrentRCStage3EpisodeHeaderTargetAudit();

inline constexpr bool
    kRCStage3EpisodeHeaderTargetProductExecutable = true;
inline constexpr bool
    kRCStage3EpisodeHeaderTargetRecursivelyConsumed = false;

} // namespace matmul::v4::rc

#endif // BTX_MATMUL_MATMUL_V4_RC_STAGE3_EPISODE_HEADER_TARGET_H
