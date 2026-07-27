// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BTX_MATMUL_MATMUL_V4_RC_STAGE3_COUPLED_EXCHANGE_PERMUTATION_PRODUCT_H
#define BTX_MATMUL_MATMUL_V4_RC_STAGE3_COUPLED_EXCHANGE_PERMUTATION_PRODUCT_H

#include <matmul/matmul_v4_rc_stage3_coupled_semantic.h>

#include <array>
#include <cstdint>
#include <string>
#include <vector>

namespace matmul::v4::rc {

inline constexpr uint16_t
    kRCStage3CoupledExchangePermutationProductVersion = 1;
inline constexpr uint32_t
    kRCStage3CoupledExchangePermutationMaxRows = 1U << 20;
inline constexpr uint32_t
    kRCStage3CoupledExchangePermutationMaxStages = 4096;

enum class RCStage3CoupledExchangeStageKind : uint8_t {
    FixedSegment = 1,
    MaterialRound = 2,
};

struct RCStage3CoupledExchangeScheduleEntry {
    uint32_t schedule_index{0};
    RCStage3CoupledExchangeStageKind kind{
        RCStage3CoupledExchangeStageKind::FixedSegment};
    uint32_t barrier{0};
    uint32_t lobe_or_round{0};
    uint32_t value_count{0};

    bool operator==(
        const RCStage3CoupledExchangeScheduleEntry&) const = default;
};

struct RCStage3CoupledPermutationScheduleEntry {
    uint32_t schedule_index{0};
    uint32_t barrier{0};
    uint32_t value_count{0};
    uint32_t index_bits{0};
    std::vector<uint32_t> out_to_in_bit;
    std::vector<uint8_t> xor_mask_bit;

    bool operator==(
        const RCStage3CoupledPermutationScheduleEntry&) const = default;
};

struct RCStage3CoupledExchangePermutationWitness {
    /** Barrier-major, then lobe-major. */
    std::vector<std::vector<int64_t>> fixed_exchange_inputs;
    /** Barrier-major, then round-major. */
    std::vector<std::vector<int64_t>> material_exchange_inputs;
    /** One pre-permutation state per barrier. */
    std::vector<std::vector<int64_t>> permutation_inputs;
};

struct RCStage3CoupledExchangePermutationAirPin {
    uint16_t version{
        kRCStage3CoupledExchangePermutationProductVersion};
    RCStage3RelationEndpoint relation_endpoint{};
    uint256 statement_commitment{};
    uint256 shape_commitment{};
    uint32_t schedule_index{0};
    uint32_t logical_rows{0};
    uint32_t n_rows{0};
    uint32_t n_coeffs{0};
    uint256 challenge_seed{};
    std::vector<RCStage3EpisodeAirColumnPin> column_roots;
    uint256 pin_commitment{};
};

struct RCStage3CoupledExchangeHashExecution {
    stage3_hash_air::ShaManifest manifest;
    stage3_hash_semantic::FlatBoundaryProofBundle proof;
    RCStage3CoupledHashSemanticPin semantic_pin;
};

struct RCStage3CoupledExchangeStageProduct {
    RCStage3CoupledExchangeScheduleEntry schedule;
    std::vector<int64_t> input;
    std::vector<int64_t> output;
    /** Material rounds only: seed SHA256d followed by exact SHA-XOF blocks. */
    std::vector<RCStage3CoupledExchangeHashExecution> hash_executions;
    RCStage3CoupledExchangePermutationAirPin pin;
    air_quotient::AirQuotientProof<gkr_field::Fp3> proof;
    uint256 stage_commitment{};
};

struct RCStage3CoupledPermutationStageProduct {
    RCStage3CoupledPermutationScheduleEntry schedule;
    std::vector<int64_t> input;
    std::vector<int64_t> output;
    RCStage3CoupledExchangePermutationAirPin pin;
    air_quotient::AirQuotientProof<gkr_field::Fp3> proof;
    uint256 stage_commitment{};
};

struct RCStage3CoupledExchangePermutationProduct {
    uint16_t version{
        kRCStage3CoupledExchangePermutationProductVersion};
    uint256 statement_commitment{};
    uint256 shape_commitment{};
    uint256 sigma{};
    std::vector<RCStage3CoupledExchangeStageProduct> exchange_stages;
    std::vector<RCStage3CoupledPermutationStageProduct>
        permutation_stages;
    uint256 exchange_input_endpoint_root{};
    uint256 exchange_hash_xof_endpoint_root{};
    uint256 exchange_output_endpoint_root{};
    uint256 permutation_input_endpoint_root{};
    uint256 permutation_output_endpoint_root{};
    uint256 product_commitment{};
};

[[nodiscard]] std::vector<RCStage3CoupledExchangeScheduleEntry>
BuildRCStage3CoupledExchangeSchedule(
    const RCStage3CoupledShape& shape,
    std::string* why = nullptr);
[[nodiscard]] std::vector<RCStage3CoupledPermutationScheduleEntry>
BuildRCStage3CoupledPermutationSchedule(
    const RCStage3SuccinctProof& statement,
    const RCStage3CoupledShape& shape,
    std::string* why = nullptr);

[[nodiscard]] uint256
ComputeRCStage3CoupledExchangePermutationAirPinCommitment(
    const RCStage3CoupledExchangePermutationAirPin& pin);
[[nodiscard]] uint256
ComputeRCStage3CoupledExchangePermutationProductCommitment(
    const RCStage3CoupledExchangePermutationProduct& product);

/**
 * Bounded honest builder. It derives every output and every SHA/XOF manifest
 * from the supplied proof-owned input vectors, but does not fill proofs.
 */
/**
 * Native indexed-permutation grand-product AirConstraintSystem builders (with
 * the beta-vector/gamma fingerprint challenges baked as closure constants).
 * Exposed so the constraint-bytecode transport-lane migration can be
 * DIFFERENTIALLY tested against the exact native relation. The last six
 * constraints of each system are the two grand-product lanes; for the
 * permutation system those are the whole system, for the exchange (material)
 * system they follow the boolean/xor/limb-recompose constraints.
 */
[[nodiscard]] air_quotient::AirConstraintSystem<gkr_field::Fp3>
BuildRCStage3CoupledPermutationTransportConstraintSystem(
    const RCStage3CoupledExchangePermutationAirPin& pin);

[[nodiscard]] air_quotient::AirConstraintSystem<gkr_field::Fp3>
BuildRCStage3CoupledExchangeTransportConstraintSystem(
    const RCStage3CoupledExchangePermutationAirPin& pin);

/**
 * The twelve verifier-owned permutation challenges, packed per lane L as
 * [beta0..beta4, gamma] at indices L*6+0..5. Both the permutation and exchange
 * systems derive them identically via AddPermutationProduct.
 */
[[nodiscard]] std::array<gkr_field::Fp3, 12>
RCStage3CoupledExchangePermutationTransportChallengeVector(
    const uint256& challenge_seed, uint32_t schedule_index);

[[nodiscard]] bool BuildRCStage3CoupledExchangePermutationProduct(
    const RCStage3SuccinctProof& statement,
    const RCStage3CoupledShape& shape,
    const RCStage3CoupledExchangePermutationWitness& witness,
    RCStage3CoupledExchangePermutationProduct& out,
    std::string* why = nullptr);

/** Fill all equality/indexed-permutation and fixed-program SHA proofs. */
[[nodiscard]] bool ProveRCStage3CoupledExchangePermutationProduct(
    const RCStage3SuccinctProof& statement,
    const RCStage3CoupledShape& shape,
    const RCStage3CoupledExchangePermutationWitness& witness,
    RCStage3CoupledExchangePermutationProduct& out,
    std::string* why = nullptr);

/** Exact schedule/root validation without proof execution. */
[[nodiscard]] bool
ValidateRCStage3CoupledExchangePermutationProductSchedule(
    const RCStage3SuccinctProof& statement,
    const RCStage3CoupledShape& shape,
    const RCStage3CoupledExchangePermutationProduct& product,
    std::string* why = nullptr);

/** Execute every local AIR and every material-round SHA/XOF child. */
[[nodiscard]] bool VerifyRCStage3CoupledExchangePermutationProduct(
    const RCStage3SuccinctProof& statement,
    const RCStage3CoupledShape& shape,
    const RCStage3CoupledExchangePermutationProduct& product,
    std::string* why = nullptr);

struct RCStage3CoupledExchangePermutationProductAudit {
    bool exact_exchange_schedule{false};
    bool fixed_segment_equality_executable{false};
    bool material_seed_sha256d_executable{false};
    bool material_sha_xof_executable{false};
    bool xor_and_indexed_permutation_executable{false};
    bool exact_public_permutation_schedule{false};
    bool permutation_indexed_product_executable{false};
    bool proof_owned_endpoint_roots{false};
    bool endpoints_34_through_38_bounded_local_complete{false};
    bool external_producer_provenance_complete{false};
    bool production_streaming_complete{false};
    bool recursively_consumed{false};
    bool transitively_complete{false};
    std::string remaining;
};

[[nodiscard]] RCStage3CoupledExchangePermutationProductAudit
CurrentRCStage3CoupledExchangePermutationProductAudit();

inline constexpr bool
    kRCStage3CoupledExchangePermutationBoundedLocalExecutable = true;
inline constexpr bool
    kRCStage3CoupledExchangePermutationProductionStreamingComplete =
        false;
inline constexpr bool
    kRCStage3CoupledExchangePermutationRecursivelyConsumed = false;

} // namespace matmul::v4::rc

#endif
