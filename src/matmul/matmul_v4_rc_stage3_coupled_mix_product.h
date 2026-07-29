// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BTX_MATMUL_MATMUL_V4_RC_STAGE3_COUPLED_MIX_PRODUCT_H
#define BTX_MATMUL_MATMUL_V4_RC_STAGE3_COUPLED_MIX_PRODUCT_H

#include <matmul/matmul_v4_rc_stage3_coupled_air.h>
#include <matmul/matmul_v4_rc_stage3_episode_air.h>
#include <matmul/matmul_v4_rc_stage3_hash_semantic.h>

#include <cstdint>
#include <string>
#include <vector>

namespace matmul::v4::rc {

inline constexpr uint16_t kRCStage3CoupledMixProductVersion = 1;
inline constexpr uint32_t kRCStage3CoupledMixMaxOperations = 1U << 16;
inline constexpr uint32_t kRCStage3CoupledMixMaxInputCells = 1U << 20;

/** Arithmetic columns 0..MIX_NUM_COLS-1 retain the immutable coupled AIR
 * limb layout. Remaining columns are the verifier-derived operation schedule. */
enum RCStage3CoupledMixScheduleColumn : uint32_t {
    kRCStage3CoupledMixActive =
        coupled_air_col::MIX_NUM_COLS,
    kRCStage3CoupledMixBarrier,
    kRCStage3CoupledMixStageOrdinal,
    kRCStage3CoupledMixLogicalStage,
    kRCStage3CoupledMixPairOrdinal,
    kRCStage3CoupledMixI,
    kRCStage3CoupledMixJ,
    kRCStage3CoupledMixPi,
    kRCStage3CoupledMixPj,
    kRCStage3CoupledMixStride,
    kRCStage3CoupledMixPattern,
    kRCStage3CoupledMixMask,
    kRCStage3CoupledMixWrap,
    kRCStage3CoupledMixColumns,
};

struct RCStage3CoupledMixHashExecution {
    stage3_hash_air::ShaManifest manifest;
    stage3_hash_semantic::FlatBoundaryProofBundle proof;
};

struct RCStage3CoupledMixBarrierSeed {
    uint32_t barrier{0};
    uint32_t pattern{0};
    uint32_t mask{0};
    RCStage3CoupledMixHashExecution mix_seed;
    RCStage3CoupledMixHashExecution mask_block;
    uint256 receipt_commitment{};
};

struct RCStage3CoupledMixOperation {
    uint64_t operation_index{0};
    uint32_t barrier{0};
    uint32_t stage_ordinal{0};
    uint32_t logical_stage{0};
    uint32_t pair_ordinal{0};
    uint32_t i{0};
    uint32_t j{0};
    uint32_t pi{0};
    uint32_t pj{0};
    uint32_t stride{0};
    uint32_t pattern{0};
    uint32_t mask{0};

    bool operator==(const RCStage3CoupledMixOperation&) const = default;
};

struct RCStage3CoupledMixPin {
    uint16_t version{kRCStage3CoupledMixProductVersion};
    uint256 statement_commitment{};
    uint256 shape_commitment{};
    uint256 sigma{};
    uint256 schedule_commitment{};
    bool u64_wrap{false};
    uint32_t logical_rows{0};
    uint32_t n_rows{0};
    uint32_t n_coeffs{0};
    std::vector<RCStage3EpisodeAirColumnPin> column_roots;
    uint256 pin_commitment{};
};

struct RCStage3CoupledMixProduct {
    uint16_t version{kRCStage3CoupledMixProductVersion};
    uint256 statement_commitment{};
    uint256 shape_commitment{};
    uint256 sigma{};
    bool u64_wrap{false};
    uint32_t state_cells{0};
    std::vector<RCStage3CoupledMixBarrierSeed> barrier_seeds;
    std::vector<RCStage3CoupledMixOperation> schedule;
    uint256 schedule_commitment{};
    /** One complete pre-mix state per barrier. */
    std::vector<std::vector<int64_t>> input_states;
    /** One complete post-mix state per barrier. */
    std::vector<std::vector<int64_t>> output_states;
    RCStage3CoupledMixPin arithmetic_pin;
    air_quotient::AirQuotientProof<gkr_field::Fp3> arithmetic_proof;
    uint256 input_endpoint_root{};
    uint256 arithmetic_endpoint_root{};
    uint256 output_endpoint_root{};
    uint256 product_commitment{};
};

[[nodiscard]] bool BuildRCStage3CoupledMixSchedule(
    const RCStage3SuccinctProof& statement,
    const RCStage3CoupledShape& shape,
    const std::vector<RCStage3CoupledMixBarrierSeed>& barrier_seeds,
    std::vector<RCStage3CoupledMixOperation>& out,
    uint256& schedule_commitment,
    std::string* why = nullptr);

[[nodiscard]] uint256 ComputeRCStage3CoupledMixPinCommitment(
    const RCStage3CoupledMixPin& pin);
[[nodiscard]] uint256 ComputeRCStage3CoupledMixSeed(
    const RCStage3CoupledMixPin& pin);
[[nodiscard]] bool BuildRCStage3CoupledMixConstraintSystem(
    const RCStage3CoupledMixPin& pin,
    air_quotient::AirConstraintSystem<gkr_field::Fp3>& out,
    std::string* why = nullptr);
[[nodiscard]] bool VerifyRCStage3CoupledMixArithmeticProof(
    const RCStage3CoupledMixPin& pin,
    const air_quotient::AirQuotientProof<gkr_field::Fp3>& proof,
    std::string* why = nullptr);

/** Bounded prover helper. Verification never invokes ApplyAllToAllMix. */
[[nodiscard]] bool BuildRCStage3CoupledMixProduct(
    const RCStage3SuccinctProof& statement,
    const RCStage3CoupledShape& shape,
    const std::vector<std::vector<int64_t>>& input_states,
    RCStage3CoupledMixProduct& out,
    std::string* why = nullptr);
[[nodiscard]] bool ProveRCStage3CoupledMixProduct(
    const RCStage3SuccinctProof& statement,
    const RCStage3CoupledShape& shape,
    const std::vector<std::vector<int64_t>>& input_states,
    RCStage3CoupledMixProduct& out,
    std::string* why = nullptr);
[[nodiscard]] bool ValidateRCStage3CoupledMixProductSchedule(
    const RCStage3SuccinctProof& statement,
    const RCStage3CoupledShape& shape,
    const RCStage3CoupledMixProduct& product,
    std::string* why = nullptr);
[[nodiscard]] bool VerifyRCStage3CoupledMixProduct(
    const RCStage3SuccinctProof& statement,
    const RCStage3CoupledShape& shape,
    const RCStage3CoupledMixProduct& product,
    std::string* why = nullptr);

struct RCStage3CoupledMixProductAudit {
    bool immutable_full_butterfly_schedule{false};
    bool mix_seed_and_mask_sha_executed{false};
    bool index_relabelling_bound{false};
    bool complete_u64_limb_range_executed{false};
    bool signed_overflow_excluded{false};
    bool all_sum_difference_arithmetic_executed{false};
    bool stage_state_equality_executed{false};
    bool endpoints_39_40_41_bounded_local_complete{false};
    bool producer_provenance_complete{false};
    bool production_streaming_complete{false};
    bool recursively_consumed{false};
    bool transitively_complete{false};
    std::string remaining;
};

[[nodiscard]] RCStage3CoupledMixProductAudit
CurrentRCStage3CoupledMixProductAudit();

inline constexpr bool kRCStage3CoupledMixBoundedLocalProductExecutable =
    true;
inline constexpr bool kRCStage3CoupledMixProductionStreamingComplete =
    false;

} // namespace matmul::v4::rc

#endif // BTX_MATMUL_MATMUL_V4_RC_STAGE3_COUPLED_MIX_PRODUCT_H
