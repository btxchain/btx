// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BTX_MATMUL_MATMUL_V4_RC_STAGE3_MULTIROW_V11_SPECIALIZED_CHIPS_H
#define BTX_MATMUL_MATMUL_V4_RC_STAGE3_MULTIROW_V11_SPECIALIZED_CHIPS_H

#include <matmul/matmul_v4_rc_stage3_multirow_v11_normalized_program.h>
#include <matmul/matmul_v4_rc_stage3_multirow_v11_relation_shards.h>

#include <array>
#include <cstdint>
#include <string>
#include <vector>

namespace matmul::v4::rc::stage3_multirow_v11_specialized_chips {

namespace aq = air_quotient;
namespace cb = constraint_bytecode;
namespace gf = gkr_field;
namespace np = stage3_multirow_v11_normalized_program;
namespace pa = stage3_poseidon_air;
namespace pj = stage3_multirow_v11_parent_join;
namespace rs = stage3_multirow_v11_relation_shards;

inline constexpr uint16_t kSpecializedChipsVersionV1 = 1;
inline constexpr uint32_t kVerifierQueriesV1 = 64;

inline constexpr uint32_t kPoseidonRoundsV1 =
    alg_hash::kAlgHashFullRounds +
    alg_hash::kAlgHashPartialRounds;
inline constexpr uint32_t kPoseidonRowsPerQueryV1 = 32;
inline constexpr uint32_t kPoseidonActiveRowsPerQueryV1 =
    kPoseidonRoundsV1;
inline constexpr uint32_t kPoseidonTraceRowsV1 =
    kVerifierQueriesV1 * kPoseidonRowsPerQueryV1;

inline constexpr uint32_t kCanonicalSplitsV1 =
    pj::kPublicFieldSlotsV1 +
    pj::kCandidateDigestLimbsV1;
inline constexpr uint32_t kCanonicalSplitRowsV1 = 64;
inline constexpr uint32_t kCanonicalSplitRealRowsV1 =
    kVerifierQueriesV1 *
    kCanonicalSplitsV1 *
    kCanonicalSplitRowsV1;
inline constexpr uint32_t kCanonicalSplitTraceRowsV1 =
    1U << 15;

static_assert(kPoseidonRoundsV1 == 30);
static_assert(kPoseidonTraceRowsV1 == 2048);
static_assert(kCanonicalSplitsV1 == 7);
static_assert(kCanonicalSplitRealRowsV1 == 28672);
static_assert(kCanonicalSplitTraceRowsV1 == 32768);

struct PoseidonDataflowAuditV1 {
    uint32_t generic_programs{0};
    uint64_t generic_instructions{0};
    uint32_t generic_poseidon_columns{0};
    uint32_t boundary_input_columns{0};
    uint32_t boundary_output_columns{0};
    uint32_t eliminated_internal_columns{0};
    uint32_t external_poseidon_references{0};
    uint32_t distinct_external_poseidon_columns{0};
    uint32_t forbidden_internal_references{0};
    bool exact_poseidon_program_prefix{false};
    bool only_inputs_and_final_outputs_escape{false};
    bool no_auxiliary_column_escapes{false};
    bool substitution_dataflow_precondition{false};
    std::string note;
};

[[nodiscard]] PoseidonDataflowAuditV1
AuditPoseidonSubstitutionDataflowV1(
    const cb::ProgramTable& generic_table);

struct PoseidonRoundLayoutV1 {
    std::array<uint32_t, alg_hash::kAlgHashT> state{};
    std::array<uint32_t, alg_hash::kAlgHashT> x{};
    std::array<uint32_t, alg_hash::kAlgHashT> x2{};
    std::array<uint32_t, alg_hash::kAlgHashT> x4{};
    std::array<uint32_t, alg_hash::kAlgHashT> x6{};
    std::array<uint32_t, alg_hash::kAlgHashT> sbox{};
    std::array<uint32_t, alg_hash::kAlgHashT> output{};
    std::array<uint32_t, alg_hash::kAlgHashT> input_claim{};
    std::array<uint32_t, alg_hash::kAlgHashT> output_claim{};
    uint32_t first{0};
    uint32_t last{0};
    uint32_t continue_round{0};
    uint32_t active_round{0};
    std::array<
        std::array<uint32_t, alg_hash::kAlgHashT>,
        alg_hash::kAlgHashT> pre_matrix{};
    std::array<uint32_t, alg_hash::kAlgHashT> round_constant{};
    std::array<uint32_t, alg_hash::kAlgHashT> sbox_active{};
    std::array<
        std::array<uint32_t, alg_hash::kAlgHashT>,
        alg_hash::kAlgHashT> post_matrix{};
    uint32_t n_columns{0};
};

[[nodiscard]] PoseidonRoundLayoutV1
CanonicalPoseidonRoundLayoutV1();

[[nodiscard]] bool BuildPoseidonRoundProgramTableV1(
    cb::ProgramTable& out,
    std::string* why = nullptr);

struct PoseidonRoundProductV1 {
    PoseidonRoundLayoutV1 layout{};
    cb::ProgramTable program_table{};
    aq::AirConstraintSystem<gf::Fp3> cs{};
    std::vector<std::vector<gf::Fp3>> columns;
    std::vector<uint32_t> preprocessed_columns;
    uint256 preprocessed_row_group_root{};
    std::array<alg_hash::State, kVerifierQueriesV1> claimed_inputs{};
    std::array<alg_hash::State, kVerifierQueriesV1> claimed_outputs{};
    uint32_t trace_rows{0};
    uint32_t active_rows{0};
    uint32_t scheduler_reserve_rows{0};
    uint32_t trace_columns{0};
    uint32_t programs{0};
    uint64_t instructions{0};
    uint32_t max_degree{0};
    uint64_t violations{0};
    bool exact_native_outputs{false};
    bool exact_round_schedule_root_pinned{false};
    bool executable{false};
    bool recursive_authority_ready{false};
    bool valid{false};
    std::string note;
};

[[nodiscard]] PoseidonRoundProductV1
BuildPoseidonRoundProductV1(
    const std::array<
        alg_hash::State,
        kVerifierQueriesV1>& inputs,
    const std::array<
        alg_hash::State,
        kVerifierQueriesV1>& claimed_outputs);

struct CanonicalSplitInputV1 {
    uint64_t raw{0};
    uint64_t expected{0};
    bool active{true};
    bool expected_is_public{false};
};

struct CanonicalSplitLayoutV1 {
    uint32_t bit{0};
    uint32_t low_sum_before{0};
    uint32_t low_sum_after{0};
    uint32_t high_sum_before{0};
    uint32_t high_sum_after{0};
    uint32_t high_and_before{0};
    uint32_t high_and_after{0};
    uint32_t claim_lo{0};
    uint32_t claim_hi{0};
    uint32_t expected_lo{0};
    uint32_t expected_hi{0};
    uint32_t replay{0};
    uint32_t split_active{0};
    uint32_t low_inverse{0};
    uint32_t low_nonzero{0};
    uint32_t first{0};
    uint32_t last{0};
    uint32_t continue_bit{0};
    uint32_t low_mask{0};
    uint32_t high_mask{0};
    uint32_t high_first{0};
    uint32_t weight{0};
    uint32_t expected_active{0};
    uint32_t query_ordinal{0};
    uint32_t split_ordinal{0};
    uint32_t bit_ordinal{0};
    uint32_t n_columns{0};
};

[[nodiscard]] CanonicalSplitLayoutV1
CanonicalSplitChipLayoutV1();

[[nodiscard]] bool BuildCanonicalSplitProgramTableV1(
    cb::ProgramTable& out,
    std::string* why = nullptr);

struct CanonicalSplitProductV1 {
    CanonicalSplitLayoutV1 layout{};
    cb::ProgramTable program_table{};
    aq::AirConstraintSystem<gf::Fp3> cs{};
    std::vector<std::vector<gf::Fp3>> columns;
    std::vector<uint32_t> preprocessed_columns;
    uint256 preprocessed_row_group_root{};
    uint32_t trace_rows{0};
    uint32_t active_rows{0};
    uint32_t scheduler_reserve_rows{0};
    uint32_t trace_columns{0};
    uint32_t programs{0};
    uint64_t instructions{0};
    uint32_t max_degree{0};
    uint64_t violations{0};
    bool exact_seven_split_schedule{false};
    bool goldilocks_alias_rejected{false};
    bool exact_schedule_root_pinned{false};
    bool executable{false};
    bool recursive_authority_ready{false};
    bool valid{false};
    std::string note;
};

[[nodiscard]] CanonicalSplitProductV1
BuildCanonicalSplitProductV1(
    const std::array<
        std::array<
            CanonicalSplitInputV1,
            kCanonicalSplitsV1>,
        kVerifierQueriesV1>& inputs);

[[nodiscard]] uint64_t RecountViolationsV1(
    const aq::AirConstraintSystem<gf::Fp3>& cs,
    const std::vector<std::vector<gf::Fp3>>& columns,
    const std::vector<uint32_t>& preprocessed_columns,
    const uint256& expected_preprocessed_root);

struct CostAuditV1 {
    uint64_t generic_total_instructions{0};
    uint64_t generic_poseidon_instructions{0};
    uint64_t generic_transcript_instructions{0};
    uint64_t generic_unrolled_split_instructions{0};
    uint64_t retained_parent_instructions{0};
    uint64_t specialized_poseidon_instructions{0};
    uint64_t specialized_split_instructions{0};
    uint64_t specialized_total_instructions{0};
    uint32_t fixedpoint_instruction_cap{0};
    uint32_t instruction_headroom{0};
    uint32_t generic_relation_shards{0};
    uint32_t specialized_relation_shards{0};
    bool exact_generic_partition{false};
    bool specialized_cost_below_fixedpoint_cap{false};
    bool generic_fallback_preserved{false};
    bool specialized_recursive_receipt_consumption_executed{false};
    bool recursive_authority_ready{false};
    bool valid_foundation{false};
    std::string note;
};

[[nodiscard]] CostAuditV1 AssessSpecializedCostV1(
    const cb::ProgramTable& generic_table,
    const cb::ProgramTable& poseidon_round_table,
    const cb::ProgramTable& canonical_split_table);

inline constexpr bool kSpecializedVerifierChipsExecutableV1 = true;
inline constexpr bool kSpecializedRecursiveReceiptConsumptionReadyV1 = false;
inline constexpr bool kSpecializedRecursiveAuthorityReadyV1 = false;
static_assert(kSpecializedVerifierChipsExecutableV1);
static_assert(!kSpecializedRecursiveReceiptConsumptionReadyV1);
static_assert(!kSpecializedRecursiveAuthorityReadyV1);

} // namespace matmul::v4::rc::stage3_multirow_v11_specialized_chips

#endif
