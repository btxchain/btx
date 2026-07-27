// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BTX_MATMUL_MATMUL_V4_RC_STAGE3_COUPLED_GEMM_PRODUCT_H
#define BTX_MATMUL_MATMUL_V4_RC_STAGE3_COUPLED_GEMM_PRODUCT_H

#include <matmul/matmul_v4_rc_stage3_coupled.h>
#include <matmul/matmul_v4_rc_stage3_episode_air.h>
#include <matmul/matmul_v4_rc_stage3_relation_closure.h>

#include <cstdint>
#include <string>
#include <vector>

namespace matmul::v4::rc {

inline constexpr uint16_t kRCStage3CoupledGemmProductVersion = 1;

enum RCStage3CoupledGemmDotColumn : uint32_t {
    kRCStage3CoupledGemmActive = 0,
    kRCStage3CoupledGemmStart,
    kRCStage3CoupledGemmEnd,
    kRCStage3CoupledGemmA,
    kRCStage3CoupledGemmB,
    kRCStage3CoupledGemmY,
    kRCStage3CoupledGemmProduct,
    kRCStage3CoupledGemmAccumulatorBefore,
    kRCStage3CoupledGemmAccumulatorAfter,
    kRCStage3CoupledGemmColumns,
};

struct RCStage3CoupledGemmScheduleEntry {
    uint64_t schedule_index{0};
    uint32_t barrier{0};
    uint32_t lobe{0};
    uint32_t page_slot{0};
    uint32_t page_id{0};

    bool operator==(
        const RCStage3CoupledGemmScheduleEntry&) const = default;
};

struct RCStage3CoupledGemmDotPin {
    uint16_t version{kRCStage3CoupledGemmProductVersion};
    uint256 statement_commitment{};
    uint256 shape_commitment{};
    uint256 schedule_commitment{};
    uint64_t schedule_index{0};
    uint64_t output_tile_index{0};
    uint32_t contraction_size{0};
    uint32_t logical_rows{0};
    uint32_t n_rows{0};
    uint32_t n_coeffs{0};
    std::vector<RCStage3EpisodeAirColumnPin> column_roots;
    uint256 pin_commitment{};
};

struct RCStage3CoupledGemmTileProof {
    uint64_t output_tile_index{0};
    RCStage3CoupledGemmDotPin pin;
    air_quotient::AirQuotientProof<gkr_field::Fp3> proof;
};

/** Prover-supplied flat openings for one immutable scheduled GEMM. */
struct RCStage3CoupledGemmOpening {
    std::vector<int8_t> operand_a;
    std::vector<int8_t> operand_b;
    std::vector<int64_t> output_y;
};

struct RCStage3CoupledGemmInstanceProduct {
    RCStage3CoupledGemmScheduleEntry schedule;
    std::vector<int8_t> operand_a;
    std::vector<int8_t> operand_b;
    std::vector<int64_t> output_y;
    uint256 operand_a_root{};
    uint256 operand_b_root{};
    uint256 output_y_root{};
    std::vector<RCStage3CoupledGemmTileProof> tiles;
    uint256 instance_receipt_commitment{};
};

struct RCStage3CoupledGemmProduct {
    uint16_t version{kRCStage3CoupledGemmProductVersion};
    uint256 statement_commitment{};
    uint256 shape_commitment{};
    uint256 sigma{};
    uint256 schedule_commitment{};
    uint64_t expected_gemms{0};
    uint64_t expected_output_tiles{0};
    std::vector<RCStage3CoupledGemmInstanceProduct> gemms;
    uint256 operand_a_endpoint_root{};
    uint256 operand_b_endpoint_root{};
    uint256 output_y_endpoint_root{};
    uint256 product_commitment{};
};

[[nodiscard]] uint256 ComputeRCStage3CoupledGemmDotPinCommitment(
    const RCStage3CoupledGemmDotPin& pin);
[[nodiscard]] uint256 ComputeRCStage3CoupledGemmDotSeed(
    const RCStage3CoupledGemmDotPin& pin);
[[nodiscard]] bool BuildRCStage3CoupledGemmDotConstraintSystem(
    const RCStage3CoupledGemmDotPin& pin,
    air_quotient::AirConstraintSystem<gkr_field::Fp3>& out,
    std::string* why = nullptr);
[[nodiscard]] bool VerifyRCStage3CoupledGemmDotProof(
    const RCStage3CoupledGemmDotPin& pin,
    const air_quotient::AirQuotientProof<gkr_field::Fp3>& proof,
    std::string* why = nullptr);

[[nodiscard]] bool BuildRCStage3CoupledGemmSchedule(
    const RCStage3SuccinctProof& statement,
    const RCStage3CoupledShape& shape,
    std::vector<RCStage3CoupledGemmScheduleEntry>& out,
    uint256& schedule_commitment,
    std::string* why = nullptr);

/** Native prover helper. Verification never calls an exact GEMM oracle. */
[[nodiscard]] bool BuildRCStage3CoupledGemmProduct(
    const RCStage3SuccinctProof& statement,
    const RCStage3CoupledShape& shape,
    const std::vector<RCStage3CoupledGemmOpening>& openings,
    RCStage3CoupledGemmProduct& out,
    std::string* why = nullptr);
[[nodiscard]] bool ProveRCStage3CoupledGemmProduct(
    const RCStage3SuccinctProof& statement,
    const RCStage3CoupledShape& shape,
    const std::vector<RCStage3CoupledGemmOpening>& openings,
    RCStage3CoupledGemmProduct& out,
    std::string* why = nullptr);

/** Exact schedule/root validation only; performs no matrix multiplication. */
[[nodiscard]] bool ValidateRCStage3CoupledGemmSchedule(
    const RCStage3SuccinctProof& statement,
    const RCStage3CoupledShape& shape,
    const RCStage3CoupledGemmProduct& product,
    std::string* why = nullptr);
/** Executes every scheduled dot-product quotient proof. */
[[nodiscard]] bool VerifyRCStage3CoupledGemmProduct(
    const RCStage3SuccinctProof& statement,
    const RCStage3CoupledShape& shape,
    const RCStage3CoupledGemmProduct& product,
    std::string* why = nullptr);

struct RCStage3CoupledGemmProductAudit {
    bool immutable_shape_derived_schedule{false};
    bool every_a_opening_bound{false};
    bool every_b_opening_bound{false};
    bool every_y_opening_bound{false};
    bool every_dot_air_executed{false};
    bool endpoints_30_through_32_locally_complete{false};
    bool bank_page_producer_provenance_complete{false};
    bool prior_state_producer_provenance_complete{false};
    bool production_streaming_complete{false};
    bool recursively_consumed{false};
    bool transitively_complete{false};
    std::string remaining;
};

[[nodiscard]] RCStage3CoupledGemmProductAudit
CurrentRCStage3CoupledGemmProductAudit();

inline constexpr bool kRCStage3CoupledGemmLocalProductExecutable = true;
inline constexpr bool kRCStage3CoupledGemmTransitivelyComplete = false;

} // namespace matmul::v4::rc

#endif
