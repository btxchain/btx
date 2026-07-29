// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BTX_MATMUL_MATMUL_V4_RC_STAGE3_EPISODE_SEMANTIC_H
#define BTX_MATMUL_MATMUL_V4_RC_STAGE3_EPISODE_SEMANTIC_H

#include <matmul/matmul_v4_rc_air_quotient.h>
#include <matmul/matmul_v4_rc_stage3_hash_semantic.h>
#include <matmul/matmul_v4_rc_stage3_relation_closure.h>

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

namespace matmul::v4::rc {

/**
 * Proof-owned memory seam shared by all twenty-six episode endpoints.
 *
 * A semantic relation normally computes a vector V in one proof while its
 * consumer uses V in another.  Hashing the words "V has root R" into two
 * receipts is not an equality proof.  This construction instead commits the
 * complete, canonically addressed vector as an AIR column:
 *
 *   producer VALUE root == memory VALUE root
 *   memory EXPORT(r)     == memory VALUE(r), for every row r
 *
 * The first equality is exact commitment-root equality.  The second is a
 * degree-one constraint in the executed quotient proof.  ACTIVE, ADDRESS,
 * REMAINING, ENDPOINT and ROLE are verifier-regenerated preprocessed columns,
 * so omission, reordering, address substitution and endpoint relabelling
 * change the accepted statement.
 *
 * This is the commitment/opening half of semantic closure.  It deliberately
 * does not pretend that authenticating a vector proves how it was computed.
 * The endpoint audit below keeps `semantic_relation_complete` separate.
 */
inline constexpr uint32_t kRCStage3EpisodeSemanticMemoryMagic =
    0x314d5345U; // "ESM1"
inline constexpr uint16_t kRCStage3EpisodeSemanticMemoryVersion = 1;
inline constexpr uint32_t kRCStage3EpisodeSemanticEndpointCount = 26;
inline constexpr uint32_t kRCStage3EpisodeSemanticMaxRows = 1U << 20;

enum RCStage3EpisodeSemanticMemoryColumn : uint32_t {
    kRCStage3EpisodeMemoryActive = 0,
    kRCStage3EpisodeMemoryAddress,
    kRCStage3EpisodeMemoryRemaining,
    kRCStage3EpisodeMemoryEndpoint,
    kRCStage3EpisodeMemoryRole,
    kRCStage3EpisodeMemoryValue,
    kRCStage3EpisodeMemoryExport,
    kRCStage3EpisodeMemoryColumns,
};

struct RCStage3EpisodeSemanticMemoryManifest {
    uint32_t magic{kRCStage3EpisodeSemanticMemoryMagic};
    uint16_t version{kRCStage3EpisodeSemanticMemoryVersion};
    RCStage3RelationEndpoint endpoint{};
    RCStage3RelationRole role{};
    uint256 statement_commitment{};
    uint64_t instance_count{0};
    uint32_t logical_rows{0};
    uint32_t n_rows{0};
    uint64_t address_begin{0};
    uint64_t address_stride{0};
    /** Root of the exact producer proof column, at n_coeffs == n_rows. */
    uint256 canonical_value_root{};
    /** Commitment to the complete verifier-owned address/type schedule. */
    uint256 schedule_commitment{};
    /** Commitment to every manifest field above. */
    uint256 manifest_commitment{};

    bool operator==(const RCStage3EpisodeSemanticMemoryManifest&) const =
        default;
};

struct RCStage3EpisodeSemanticMemoryProof {
    uint16_t version{kRCStage3EpisodeSemanticMemoryVersion};
    uint256 manifest_commitment{};
    air_quotient::AirQuotientProof<gkr_field::Fp3> quotient;
};

struct RCStage3EpisodeSemanticMemoryShard {
    uint32_t shard_index{0};
    uint64_t value_begin{0};
    RCStage3EpisodeSemanticMemoryManifest manifest;
    RCStage3EpisodeSemanticMemoryProof proof;
};

struct RCStage3EpisodeSemanticMemoryBundle {
    uint16_t version{kRCStage3EpisodeSemanticMemoryVersion};
    RCStage3RelationEndpoint endpoint{};
    uint256 statement_commitment{};
    uint64_t total_instance_count{0};
    uint64_t address_begin{0};
    uint64_t address_stride{0};
    std::vector<RCStage3EpisodeSemanticMemoryShard> shards;
    uint256 bundle_commitment{};
};

/** Deterministic owning role of episode endpoint ids 1..26. */
[[nodiscard]] std::optional<RCStage3RelationRole>
RCStage3EpisodeEndpointRole(RCStage3RelationEndpoint endpoint);

/** Root used by the memory proof. Values are padded with zero to n_rows. */
[[nodiscard]] std::optional<uint256>
ComputeRCStage3EpisodeSemanticValueRoot(
    const std::vector<gkr_field::Fp3>& values,
    uint32_t logical_rows,
    uint32_t n_rows,
    std::string* why = nullptr);

[[nodiscard]] std::optional<RCStage3EpisodeSemanticMemoryManifest>
BuildRCStage3EpisodeSemanticMemoryManifest(
    RCStage3RelationEndpoint endpoint,
    const uint256& statement_commitment,
    uint64_t instance_count,
    uint32_t logical_rows,
    uint64_t address_begin,
    uint64_t address_stride,
    const uint256& canonical_value_root,
    std::string* why = nullptr);

[[nodiscard]] bool ValidateRCStage3EpisodeSemanticMemoryManifest(
    const RCStage3EpisodeSemanticMemoryManifest& manifest,
    std::string* why = nullptr);

[[nodiscard]] bool BuildRCStage3EpisodeSemanticMemoryConstraintSystem(
    const RCStage3EpisodeSemanticMemoryManifest& manifest,
    air_quotient::AirConstraintSystem<gkr_field::Fp3>& out,
    std::string* why = nullptr);

[[nodiscard]] bool BuildRCStage3EpisodeSemanticMemoryWitness(
    const RCStage3EpisodeSemanticMemoryManifest& manifest,
    const std::vector<gkr_field::Fp3>& values,
    std::vector<std::vector<gkr_field::Fp3>>& out,
    std::string* why = nullptr);

[[nodiscard]] uint256 ComputeRCStage3EpisodeSemanticMemorySeed(
    const RCStage3EpisodeSemanticMemoryManifest& manifest);

[[nodiscard]] bool ProveRCStage3EpisodeSemanticMemory(
    const RCStage3EpisodeSemanticMemoryManifest& manifest,
    const std::vector<gkr_field::Fp3>& values,
    RCStage3EpisodeSemanticMemoryProof& out,
    std::string* why = nullptr);

[[nodiscard]] bool VerifyRCStage3EpisodeSemanticMemory(
    const uint256& expected_statement_commitment,
    const RCStage3EpisodeSemanticMemoryManifest& manifest,
    const RCStage3EpisodeSemanticMemoryProof& proof,
    std::string* why = nullptr);

/** Exact V1 nonrecursive partition. Roots must contain precisely
 * ceil(total_instance_count / kRCStage3EpisodeSemanticMaxRows) entries. */
[[nodiscard]] bool BuildRCStage3EpisodeSemanticMemoryShardManifests(
    RCStage3RelationEndpoint endpoint,
    const uint256& statement_commitment,
    uint64_t total_instance_count,
    uint64_t address_begin,
    uint64_t address_stride,
    const std::vector<uint256>& canonical_value_roots,
    std::vector<RCStage3EpisodeSemanticMemoryShard>& out,
    std::string* why = nullptr);

[[nodiscard]] uint256 ComputeRCStage3EpisodeSemanticMemoryBundleCommitment(
    const RCStage3EpisodeSemanticMemoryBundle& bundle);

/** Honest flat prover. Production-scale callers may stream equivalent shards;
 * this convenience API owns the complete input vector. */
[[nodiscard]] bool ProveRCStage3EpisodeSemanticMemoryBundle(
    RCStage3RelationEndpoint endpoint,
    const uint256& statement_commitment,
    uint64_t address_begin,
    uint64_t address_stride,
    const std::vector<gkr_field::Fp3>& values,
    RCStage3EpisodeSemanticMemoryBundle& out,
    std::string* why = nullptr);

/** Executes every quotient and rejects any missing, duplicate, reordered,
 * resized, relabelled or noncontiguous shard. */
[[nodiscard]] bool VerifyRCStage3EpisodeSemanticMemoryBundle(
    RCStage3RelationEndpoint expected_endpoint,
    const uint256& expected_statement_commitment,
    uint64_t expected_total_instance_count,
    uint64_t expected_address_begin,
    uint64_t expected_address_stride,
    const std::vector<uint256>& expected_canonical_value_roots,
    const RCStage3EpisodeSemanticMemoryBundle& bundle,
    std::string* why = nullptr);

struct RCStage3EpisodeSemanticEndpointAudit {
    RCStage3RelationEndpoint endpoint{};
    RCStage3RelationRole role{};
    bool canonical_schedule_executable{false};
    bool proof_owned_memory_executable{false};
    bool canonical_root_authenticated{false};
    bool same_trace_export_constrained{false};
    bool local_semantic_air_available{false};
    bool semantic_relation_complete{false};
    bool recursively_consumed{false};
    std::string source;
    std::string remaining;
};

/**
 * Exact twenty-six-entry ledger.  A true memory bit describes executable
 * code in this module. `semantic_relation_complete` remains true only where
 * the repository actually executes both the relation and its authenticated
 * memory edge; it is never inferred from a manifest or claimed receipt.
 */
[[nodiscard]] std::vector<RCStage3EpisodeSemanticEndpointAudit>
CurrentRCStage3EpisodeSemanticEndpointAudit();

// ---------------------------------------------------------------------------
// Episode digest / target comparison.
// ---------------------------------------------------------------------------

inline constexpr uint32_t kRCStage3EpisodePowRows = 32;
enum RCStage3EpisodePowColumn : uint32_t {
    kRCStage3EpisodePowDigestByte = 0,
    kRCStage3EpisodePowTargetByte,
    kRCStage3EpisodePowBorrow,
    kRCStage3EpisodePowBorrowOut,
    kRCStage3EpisodePowDiffBitBase,
    kRCStage3EpisodePowColumns =
        kRCStage3EpisodePowDiffBitBase + 8,
};

struct RCStage3EpisodePowPin {
    uint16_t version{kRCStage3EpisodeSemanticMemoryVersion};
    uint256 statement_commitment{};
    uint256 episode_digest{};
    uint256 target{};
    uint256 pin_commitment{};

    bool operator==(const RCStage3EpisodePowPin&) const = default;
};

struct RCStage3EpisodePowProof {
    uint16_t version{kRCStage3EpisodeSemanticMemoryVersion};
    uint256 pin_commitment{};
    air_quotient::AirQuotientProof<gkr_field::Fp3> quotient;
};

[[nodiscard]] std::optional<RCStage3EpisodePowPin>
BuildRCStage3EpisodePowPin(
    const RCStage3SuccinctProof& statement,
    std::string* why = nullptr);
[[nodiscard]] bool BuildRCStage3EpisodePowConstraintSystem(
    const RCStage3EpisodePowPin& pin,
    air_quotient::AirConstraintSystem<gkr_field::Fp3>& out,
    std::string* why = nullptr);
[[nodiscard]] bool BuildRCStage3EpisodePowWitness(
    const RCStage3EpisodePowPin& pin,
    std::vector<std::vector<gkr_field::Fp3>>& out,
    std::string* why = nullptr);
[[nodiscard]] uint256 ComputeRCStage3EpisodePowSeed(
    const RCStage3EpisodePowPin& pin);
[[nodiscard]] bool ProveRCStage3EpisodePow(
    const RCStage3SuccinctProof& statement,
    RCStage3EpisodePowProof& out,
    std::string* why = nullptr);
[[nodiscard]] bool VerifyRCStage3EpisodePow(
    const RCStage3SuccinctProof& statement,
    const RCStage3EpisodePowPin& pin,
    const RCStage3EpisodePowProof& proof,
    std::string* why = nullptr);

// ---------------------------------------------------------------------------
// Typed flat hash/XOF relation + semantic-memory composition.
// ---------------------------------------------------------------------------

struct RCStage3EpisodeHashSemanticBinding {
    stage3_hash_semantic::BoundaryPort port{
        stage3_hash_semantic::BoundaryPort::ExternalThenFinal};
    RCStage3EpisodeSemanticMemoryManifest memory_manifest;
    RCStage3EpisodeSemanticMemoryProof memory_proof;
};

/**
 * Canonical address/root pin for a complete fixed-program boundary vector.
 * The endpoint and boundary port determine the address namespace; callers
 * cannot choose an aliasing address range.
 */
[[nodiscard]] std::optional<RCStage3EpisodeSemanticMemoryManifest>
BuildRCStage3EpisodeHashSemanticMemoryManifest(
    const RCStage3SuccinctProof& statement,
    RCStage3RelationEndpoint endpoint,
    const std::vector<
        stage3_hash_air::FixedProgramBoundaryInstance>& boundaries,
    stage3_hash_semantic::BoundaryPort port,
    std::string* why = nullptr);

/** Honest semantic-memory prover for a typed fixed-program boundary list. */
[[nodiscard]] bool ProveRCStage3EpisodeHashSemanticBinding(
    const RCStage3SuccinctProof& statement,
    RCStage3RelationEndpoint endpoint,
    const std::vector<
        stage3_hash_air::FixedProgramBoundaryInstance>& boundaries,
    stage3_hash_semantic::BoundaryPort port,
    RCStage3EpisodeHashSemanticBinding& out,
    std::string* why = nullptr);
[[nodiscard]] bool VerifyRCStage3EpisodeHashSemanticBinding(
    const RCStage3SuccinctProof& statement,
    RCStage3RelationEndpoint endpoint,
    const std::vector<
        stage3_hash_air::FixedProgramBoundaryInstance>& boundaries,
    const RCStage3EpisodeHashSemanticBinding& binding,
    std::string* why = nullptr);

[[nodiscard]] bool VerifyRCStage3EpisodeShaSemantic(
    const RCStage3SuccinctProof& statement,
    RCStage3RelationEndpoint endpoint,
    const stage3_hash_air::ShaManifest& manifest,
    const stage3_hash_semantic::FlatBoundaryProofBundle& hash_bundle,
    const RCStage3EpisodeHashSemanticBinding& binding,
    std::string* why = nullptr);
[[nodiscard]] bool VerifyRCStage3EpisodeCounterXofSemantic(
    const RCStage3SuccinctProof& statement,
    RCStage3RelationEndpoint endpoint,
    const stage3_hash_air::CounterXofManifest& manifest,
    const stage3_hash_semantic::FlatBoundaryProofBundle& hash_bundle,
    const RCStage3EpisodeHashSemanticBinding& binding,
    std::string* why = nullptr);
[[nodiscard]] bool VerifyRCStage3EpisodeChaChaSemantic(
    const RCStage3SuccinctProof& statement,
    RCStage3RelationEndpoint endpoint,
    const stage3_hash_air::ChaChaConsumptionManifest& manifest,
    const stage3_hash_semantic::FlatBoundaryProofBundle& hash_bundle,
    const RCStage3EpisodeHashSemanticBinding& binding,
    std::string* why = nullptr);
[[nodiscard]] bool VerifyRCStage3EpisodeTileTreeSemantic(
    const RCStage3SuccinctProof& statement,
    RCStage3RelationEndpoint endpoint,
    const stage3_hash_air::TileTreeManifest& manifest,
    const stage3_hash_semantic::FlatBoundaryProofBundle& hash_bundle,
    const RCStage3EpisodeHashSemanticBinding& binding,
    std::string* why = nullptr);
[[nodiscard]] bool VerifyRCStage3EpisodeDirectSha256dSemantic(
    const RCStage3SuccinctProof& statement,
    RCStage3RelationEndpoint endpoint,
    const stage3_hash_air::DirectSha256dManifest& manifest,
    const stage3_hash_semantic::FlatBoundaryProofBundle& hash_bundle,
    const RCStage3EpisodeHashSemanticBinding& binding,
    std::string* why = nullptr);

inline constexpr bool kRCStage3EpisodeSemanticMemoryExecutable = true;
inline constexpr bool kRCStage3EpisodePowComparisonExecutable = true;
inline constexpr bool kRCStage3EpisodeFlatHashMemoryBindingExecutable = true;
inline constexpr bool kRCStage3EpisodeSemanticRelationsComplete = false;

} // namespace matmul::v4::rc

#endif // BTX_MATMUL_MATMUL_V4_RC_STAGE3_EPISODE_SEMANTIC_H
