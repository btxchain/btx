// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BTX_MATMUL_MATMUL_V4_RC_STAGE3_EPISODE_RELATION_PRODUCT_H
#define BTX_MATMUL_MATMUL_V4_RC_STAGE3_EPISODE_RELATION_PRODUCT_H

#include <matmul/matmul_v4_rc_stage3_episode_air.h>
#include <matmul/matmul_v4_rc_stage3_episode_semantic.h>
#include <matmul/matmul_v4_rc_stage3_gemm_extract.h>

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

namespace matmul::v4::rc {

/**
 * Exact all-instance relation products for the episode AIR fragments.
 *
 * V1 closes the direct-copy endpoint.  For each non-transposed operand edge
 * in verifier-derived Λ(params), it executes:
 *
 *   (1) WiringEqualityFp3V1 on every deterministic shard;
 *   (2) a flat semantic-memory proof for the source column;
 *   (3) a flat semantic-memory proof for the destination column;
 *   (4) exact equality of each memory VALUE root to the corresponding
 *       relation-proof column root; and
 *   (5) an ordered shard-root commitment equal to the operand root registered
 *       by that layer's immutable GEMM/Extract manifest.
 *
 * The verifier receives no values and invokes no native episode callback.
 * Omission, duplication, reordering, changed dimensions, changed addresses,
 * detached memory proofs and proof-column substitution all reject.
 *
 * This is deliberately not a strict semantic-closure claim.  The manifest's
 * registered operand roots still need equality to the executed producer/root
 * graph. Likewise, gf=a*b is only the chain end of a matrix-product sumcheck,
 * and RcSampler's fixed-program trace still needs an all-tile segmented
 * relation plus a degree-aligned memory alias. The audit API below records
 * those residuals separately.
 */
inline constexpr uint32_t kRCStage3EpisodeRelationProductMagic =
    0x31505245U; // "ERP1"
inline constexpr uint16_t kRCStage3EpisodeRelationProductVersion = 1;
inline constexpr uint64_t kRCStage3EpisodeRelationProductAddressBase =
    UINT64_C(0x5700000000000000);

enum class RCStage3EpisodeWiringOperandSlot : uint8_t {
    A = 1,
    B = 2,
};

struct RCStage3EpisodeWiringCopyScheduleEntry {
    uint32_t schedule_index{0};
    uint32_t layer_ordinal{0};
    RCStage3EpisodeWiringOperandSlot slot{
        RCStage3EpisodeWiringOperandSlot::A};
    uint32_t first_column{0};
    uint32_t n_chunks{0};
    uint64_t value_count{0};
    uint64_t address_begin{0};
    uint256 registered_vector_root{};

    bool operator==(
        const RCStage3EpisodeWiringCopyScheduleEntry&) const = default;
};

/**
 * Enumerate every and only non-transposed A/B use in Λ(params).  Transposed
 * uses belong to EpisodeWiringTranspose and are intentionally excluded.
 */
[[nodiscard]] std::optional<
    std::vector<RCStage3EpisodeWiringCopyScheduleEntry>>
BuildRCStage3EpisodeWiringCopySchedule(
    const RCStage3GemmExtractManifest& manifest,
    std::string* why = nullptr);

/**
 * V1 canonical root of one complete operand vector.  `ordered_shard_roots`
 * are roots of the exact fixed-size flat-memory partition.  The formula does
 * not include the outer manifest commitment, avoiding a root/manifest
 * fixed-point; it binds the statement, immutable tensor-column identity and
 * exact logical length.
 */
[[nodiscard]] uint256 ComputeRCStage3EpisodeWiringVectorRoot(
    const uint256& statement_commitment,
    uint32_t first_column,
    uint32_t n_chunks,
    uint64_t value_count,
    const std::vector<uint256>& ordered_shard_roots);

/** Convenience computation for an honest complete vector. */
[[nodiscard]] std::optional<uint256>
ComputeRCStage3EpisodeWiringVectorRootFromValues(
    const uint256& statement_commitment,
    uint32_t first_column,
    uint32_t n_chunks,
    const std::vector<gkr_field::Fp3>& values,
    std::string* why = nullptr);

struct RCStage3EpisodeWiringCopyAirShard {
    uint32_t shard_index{0};
    uint64_t value_begin{0};
    RCStage3EpisodeAirPublicPin pin;
    air_quotient::AirQuotientProof<gkr_field::Fp3> proof;
};

struct RCStage3EpisodeWiringCopyEdgeProduct {
    uint32_t magic{kRCStage3EpisodeRelationProductMagic};
    uint16_t version{kRCStage3EpisodeRelationProductVersion};
    RCStage3EpisodeWiringCopyScheduleEntry schedule;
    std::vector<RCStage3EpisodeWiringCopyAirShard> relation_shards;
    RCStage3EpisodeSemanticMemoryBundle source_memory;
    RCStage3EpisodeSemanticMemoryBundle destination_memory;
    uint256 product_commitment{};
};

struct RCStage3EpisodeWiringCopyClosure {
    uint32_t magic{kRCStage3EpisodeRelationProductMagic};
    uint16_t version{kRCStage3EpisodeRelationProductVersion};
    uint256 statement_commitment{};
    uint256 manifest_commitment{};
    std::vector<RCStage3EpisodeWiringCopyEdgeProduct> edges;
    uint256 closure_commitment{};
};

[[nodiscard]] uint256
ComputeRCStage3EpisodeWiringCopyEdgeProductCommitment(
    const RCStage3EpisodeWiringCopyEdgeProduct& product);
[[nodiscard]] uint256
ComputeRCStage3EpisodeWiringCopyClosureCommitment(
    const RCStage3EpisodeWiringCopyClosure& closure);

/**
 * Honest flat prover for one schedule entry.  This helper is intentionally
 * bounded by memory owned by the caller; streaming provers can produce the
 * byte-identical shard products without using it.
 */
[[nodiscard]] bool ProveRCStage3EpisodeWiringCopyEdgeProduct(
    const RCStage3SuccinctProof& statement,
    const RCStage3GemmExtractManifest& manifest,
    const RCStage3EpisodeWiringCopyScheduleEntry& expected,
    const std::vector<gkr_field::Fp3>& source,
    const std::vector<gkr_field::Fp3>& destination,
    RCStage3EpisodeWiringCopyEdgeProduct& out,
    std::string* why = nullptr);

[[nodiscard]] bool VerifyRCStage3EpisodeWiringCopyEdgeProduct(
    const RCStage3SuccinctProof& statement,
    const RCStage3GemmExtractManifest& manifest,
    const RCStage3EpisodeWiringCopyScheduleEntry& expected,
    const RCStage3EpisodeWiringCopyEdgeProduct& product,
    std::string* why = nullptr);

/**
 * Exact closure over the immutable schedule.  Verification is proof-only and
 * executes every relation and both memory proofs for every edge.
 */
[[nodiscard]] bool VerifyRCStage3EpisodeWiringCopyClosure(
    const RCStage3SuccinctProof& statement,
    const RCStage3GemmExtractManifest& manifest,
    const RCStage3EpisodeWiringCopyClosure& closure,
    std::string* why = nullptr);

struct RCStage3EpisodeRelationProductEndpointStatus {
    RCStage3RelationEndpoint endpoint{};
    bool immutable_full_schedule{false};
    bool relation_proof_executed{false};
    bool exact_memory_root_alias{false};
    bool all_instances_closed{false};
    bool producer_root_authenticated{false};
    bool recursively_consumed{false};
    std::string residual;
};

/** Exact status of the six requested local-kernel endpoints. */
[[nodiscard]] std::vector<
    RCStage3EpisodeRelationProductEndpointStatus>
CurrentRCStage3EpisodeRelationProductEndpointStatus();

inline constexpr bool
    kRCStage3EpisodeWiringCopyStrictSemanticEndpointExecutable = false;
inline constexpr bool
    kRCStage3EpisodeRelationProductRecursivelyConsumed = false;
inline constexpr bool
    kRCStage3EpisodeRelationProductAuthorityReady = false;

} // namespace matmul::v4::rc

#endif // BTX_MATMUL_MATMUL_V4_RC_STAGE3_EPISODE_RELATION_PRODUCT_H
