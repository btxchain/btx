// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BTX_MATMUL_MATMUL_V4_RC_STAGE3_EPISODE_RELATION_PRODUCT_H
#define BTX_MATMUL_MATMUL_V4_RC_STAGE3_EPISODE_RELATION_PRODUCT_H

#include <matmul/matmul_v4_rc_stage3_episode_air.h>
#include <matmul/matmul_v4_rc_stage3_episode_semantic.h>
#include <matmul/matmul_v4_rc_stage3_gemm_extract.h>
#include <matmul/matmul_v4_rc_stage3_ctl.h>
#include <matmul/matmul_v4_rc_stage3_air_quotient_codec.h>

#include <array>
#include <cstdint>
#include <optional>
#include <string>
#include <vector>

namespace matmul::v4::rc {

/**
 * Canonical proof-owned producer side of one semantic bus.
 *
 * The event tuple is public and ordered.  VALUE is deliberately absent from
 * the event: it is the literal `relation_value_column` of the same Split-RAP
 * proof that executes the owning relation.  This prevents a host-created
 * VALUE vector from being substituted for the relation witness.
 */
inline constexpr uint16_t kRCStage3ProducerBusReceiptVersionV1 = 1;
inline constexpr uint32_t kRCStage3ProducerBusReceiptMagicV1 =
    0x31524250U; // "PBR1"

struct RCStage3ProducerBusEventV1 {
    bool active{false};
    RCStage3RelationEndpoint endpoint{};
    RCStage3RelationRole semantic_role{};
    uint64_t address{0};
    uint64_t remaining{0};
    int8_t multiplicity{0};

    bool operator==(const RCStage3ProducerBusEventV1&) const = default;
};

struct RCStage3ProducerBusScheduleV1 {
    uint16_t version{kRCStage3ProducerBusReceiptVersionV1};
    uint32_t bus_id{0};
    uint32_t logical_rows{0};
    std::vector<RCStage3ProducerBusEventV1> events;
    uint256 schedule_commitment{};

    bool operator==(const RCStage3ProducerBusScheduleV1&) const = default;
};

struct RCStage3ProducerBusEpochPinV1 {
    RCStage3RelationRole relation_role{};
    uint256 schedule_commitment{};
    uint256 base_row_commitment{};

    bool operator==(const RCStage3ProducerBusEpochPinV1&) const = default;
};

struct RCStage3ProducerBusReceiptV1 {
    uint32_t magic{kRCStage3ProducerBusReceiptMagicV1};
    uint16_t version{kRCStage3ProducerBusReceiptVersionV1};
    RCStage3RelationRole relation_role{};
    uint256 statement_commitment{};
    uint256 relation_commitment{};
    RCStage3ProducerBusScheduleV1 schedule;
    RCStage3CtlChallenges challenges;
    RCStage3CtlTerminal terminal;
    uint32_t logical_rows{0};
    uint32_t n_rows{0};
    /** The exact owning-relation column used by the CTL compression. */
    uint32_t relation_value_column{0};
    uint256 relation_value_column_root{};
    uint256 base_row_commitment{};
    std::vector<uint32_t> base_column_indices;
    std::vector<uint256> prechallenge_column_roots;
    /** RUNNING1/RUNNING2 and TERM1/TERM2 in the owning relation proof. */
    std::array<uint32_t, 2> terminal_running_columns{};
    std::array<uint32_t, 2> terminal_term_columns{};
    std::array<uint256, 2> terminal_running_column_roots{};
    std::array<uint256, 2> terminal_term_column_roots{};
    uint256 public_challenge_seed{};
    uint256 public_fs_seed{};
    air_quotient::AirQuotientProof<
        gkr_field::Fp3> proof;
    std::vector<unsigned char> canonical_proof_bytes;
    uint256 proof_commitment{};
    uint256 receipt_commitment{};
};

/**
 * Verifier-owned interpretation of a producer receipt.  The receipt never
 * supplies its own constraint system or accepted column set.
 */
struct RCStage3ProducerBusVerificationInputV1 {
    RCStage3RelationRole expected_relation_role{};
    uint256 expected_statement_commitment{};
    uint256 expected_relation_commitment{};
    RCStage3ProducerBusScheduleV1 expected_schedule;
    uint32_t expected_logical_rows{0};
    uint32_t expected_n_rows{0};
    uint32_t expected_relation_value_column{0};
    std::array<uint32_t, 2>
        expected_terminal_running_columns{};
    std::array<uint32_t, 2>
        expected_terminal_term_columns{};
    air_quotient::AirConstraintSystem<gkr_field::Fp3> expected_cs;
    std::vector<uint32_t> expected_base_column_indices;
    uint256 expected_public_challenge_seed{};
    uint256 expected_public_fs_seed{};
    bool valid{false};
    std::string note;
};

[[nodiscard]] uint256 ComputeRCStage3ProducerBusScheduleCommitmentV1(
    const RCStage3ProducerBusScheduleV1& schedule);
[[nodiscard]] uint256 ComputeRCStage3ProducerBusBaseCommitmentV1(
    const RCStage3ProducerBusScheduleV1& schedule,
    const std::vector<uint32_t>& base_column_indices,
    const std::vector<uint256>& prechallenge_column_roots);
[[nodiscard]] uint256 ComputeRCStage3ProducerBusChallengeSeedV1(
    const uint256& statement_commitment,
    uint32_t bus_id,
    const std::vector<RCStage3ProducerBusEpochPinV1>&
        ordered_participants);
[[nodiscard]] uint256 ComputeRCStage3ProducerBusProofCommitmentV1(
    const std::vector<unsigned char>& canonical_proof_bytes);
[[nodiscard]] bool SerializeRCStage3ProducerBusProofV1(
    const air_quotient::AirQuotientProof<gkr_field::Fp3>& proof,
    std::vector<unsigned char>& out,
    std::string* why = nullptr);
[[nodiscard]] bool DeriveRCStage3ProducerBusChallengesV1(
    const uint256& public_challenge_seed,
    const RCStage3ProducerBusScheduleV1& schedule,
    const uint256& base_row_commitment,
    RCStage3CtlChallenges& out,
    std::string* why = nullptr);
[[nodiscard]] uint256 ComputeRCStage3ProducerBusReceiptCommitmentV1(
    const RCStage3ProducerBusReceiptV1& receipt);
[[nodiscard]] bool VerifyRCStage3ProducerBusReceiptV1(
    const RCStage3ProducerBusReceiptV1& receipt,
    const RCStage3ProducerBusVerificationInputV1& input,
    std::string* why = nullptr);
[[nodiscard]] bool VerifyRCStage3ProducerBusTerminalPairV1(
    const RCStage3ProducerBusReceiptV1& producer,
    const RCStage3ProducerBusVerificationInputV1& producer_input,
    const RCStage3ProducerBusReceiptV1& receiver,
    const RCStage3ProducerBusVerificationInputV1& receiver_input,
    const uint256& expected_public_challenge_seed,
    std::string* why = nullptr);

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

[[nodiscard]] bool
ProveRCStage3EpisodeWiringCopyReceiverBusReceiptV1(
    const RCStage3SuccinctProof& statement,
    const RCStage3GemmExtractManifest& manifest,
    const RCStage3EpisodeWiringCopyScheduleEntry& expected,
    const RCStage3EpisodeWiringCopyEdgeProduct& product,
    const std::vector<gkr_field::Fp3>& source_values,
    uint32_t shard_index,
    const uint256& public_challenge_seed,
    RCStage3ProducerBusReceiptV1& out,
    std::string* why = nullptr);

[[nodiscard]] RCStage3ProducerBusVerificationInputV1
BuildRCStage3EpisodeWiringCopyReceiverBusVerificationInputV1(
    const RCStage3EpisodeWiringCopyScheduleEntry& expected,
    const RCStage3EpisodeWiringCopyEdgeProduct& product,
    uint32_t shard_index,
    const uint256& expected_public_challenge_seed,
    const RCStage3ProducerBusReceiptV1& receipt);

[[nodiscard]] bool
VerifyRCStage3EpisodeWiringCopyReceiverBusReceiptV1(
    const RCStage3EpisodeWiringCopyScheduleEntry& expected,
    const RCStage3EpisodeWiringCopyEdgeProduct& product,
    uint32_t shard_index,
    const uint256& expected_public_challenge_seed,
    const RCStage3ProducerBusReceiptV1& receipt,
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
