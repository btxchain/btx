// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BTX_MATMUL_MATMUL_V4_RC_STAGE3_FAMILY_VM_H
#define BTX_MATMUL_MATMUL_V4_RC_STAGE3_FAMILY_VM_H

#include <matmul/matmul_v4_rc_stage3_constraint_bytecode.h>
#include <matmul/matmul_v4_rc_air_quotient_alg.h>

#include <cstdint>
#include <functional>
#include <string>
#include <vector>

namespace matmul::v4::rc::stage3_family_vm {

namespace cb = constraint_bytecode;

inline constexpr uint16_t kFamilyVmPlanVersionV1 = 1;
inline constexpr uint32_t kFamilyVmLookupLanesV1 = 2;
inline constexpr uint32_t kFamilyVmQueriesV1 = 192;

/**
 * Fixed-width family execution target.
 *
 * The original wide support inventory is moved into trace length:
 *
 *   source table      (row, global_column, value, multiplicity)
 *   instruction trace(row, program, pc, operands, result)
 *
 * Two post-R0 LogUp lanes check source reads and SSA-register reads. The
 * canonical ProgramTable is AlgHash-pinned. The resulting AIR needs a
 * constant number of physical columns independent of original relation
 * width. 193 is the concrete layout target: 32 VM/schedule columns, 16
 * two-lane lookup columns, and the existing 145-column vertical AlgHash
 * sponge/permutation block.
 */
inline constexpr uint32_t kFamilyVmCoreColumnsV1 = 32;
inline constexpr uint32_t kFamilyVmLookupColumnsV1 = 16;
inline constexpr uint32_t kFamilyVmProgramHashColumnsV1 = 145;
inline constexpr uint32_t kFamilyVmCandidateColumnsV1 =
    kFamilyVmCoreColumnsV1 +
    kFamilyVmLookupColumnsV1 +
    kFamilyVmProgramHashColumnsV1;
inline constexpr uint64_t kFamilyVmCoefficientCapV1 =
    uint64_t{1} << kRCFriMaxColumnLog2;
inline constexpr uint32_t kFamilyVmRegisterIndexBitsV1 = 20;
inline constexpr uint64_t kFamilyVmRegisterIndexStrideV1 =
    uint64_t{1} << kFamilyVmRegisterIndexBitsV1;
inline constexpr bool
    kFamilyVmUnsegmentedSplitRapExecutableV1 = true;
inline constexpr bool
    kFamilyVmSegmentedResidualFoldExecutableV1 = false;

/** The executable V1 trace is deliberately narrower than the 193-column
 * planning ceiling. Program hashing is statement-owned in V1; recursive
 * in-AIR hash replay consumes the reserved 145-column block later. */
inline constexpr uint32_t kFamilyVmExecutableColumnsV1 = 53;

struct FamilyVmProgramInventoryV1 {
    uint32_t constraint_ordinal{0};
    air_quotient::AirKind kind{
        air_quotient::AirKind::kEverywhere};
    uint32_t instructions{0};
    uint32_t current_loads{0};
    uint32_t next_loads{0};
    uint32_t register_reads{0};
    uint32_t terminal_checks{0};
    std::vector<uint32_t> register_use_multiplicity;

    bool operator==(const FamilyVmProgramInventoryV1&) const = default;
};

/**
 * Canonical schedule and multiset accounting for one relation family.
 *
 * This is not a receipt and contains no witness values. It is the immutable
 * statement needed by the executable vertical VM backend. Rebuilding the
 * plan from the consensus-pinned ProgramTable is the validation rule.
 */
struct FamilyVmPlanV1 {
    uint16_t version{kFamilyVmPlanVersionV1};
    RCStage3RelationRole role{};
    uint32_t original_trace_rows{0};
    uint32_t original_columns{0};
    uint32_t programs{0};
    uint32_t instructions_per_original_row{0};
    uint64_t source_memory_rows{0};
    uint64_t instruction_execution_rows{0};
    uint64_t logical_vertical_rows{0};
    uint64_t padded_vertical_rows{0};
    uint64_t source_read_events{0};
    uint64_t source_definition_weight{0};
    uint64_t register_read_events{0};
    uint64_t register_definition_weight{0};
    uint64_t terminal_checks{0};
    uint32_t physical_columns{kFamilyVmCandidateColumnsV1};
    uint64_t direct_query_value_bytes{0};
    uint64_t coefficient_cap{kFamilyVmCoefficientCapV1};
    uint32_t minimum_vm_segments{0};
    uint256 program_table_commitment{};
    alg_hash::Digest program_table_alg_hash{};
    uint256 schedule_commitment{};
    std::vector<uint32_t> source_load_multiplicity;
    std::vector<FamilyVmProgramInventoryV1> program_inventory;

    bool canonical_program_table{false};
    bool exact_row_program_pc_schedule{false};
    bool cyclic_next_row_semantics{false};
    bool source_read_multiset_balanced{false};
    bool register_read_multiset_balanced{false};
    bool register_key_encoding_injective{false};
    bool selector_terminal_schedule_exact{false};
    bool dual_lanes_after_r0{false};
    bool original_width_moved_to_trace_length{false};
    bool fixed_width_under_512{false};
    bool fits_single_split_rap{false};
    /** False until the quotient/FRI prover executes this plan. */
    bool split_rap_family_proof_executable{false};
    bool production_authority_ready{false};
    bool valid{false};
    std::string note;

    bool operator==(const FamilyVmPlanV1&) const = default;
};

[[nodiscard]] FamilyVmPlanV1 BuildFamilyVmPlanV1(
    const cb::ProgramTable& table,
    uint32_t original_trace_rows);

[[nodiscard]] bool ValidateFamilyVmPlanV1(
    const cb::ProgramTable& table,
    const FamilyVmPlanV1& plan,
    std::string* why = nullptr);

struct FamilyVmLookupChallengesV1 {
    gkr_field::Fp3 gamma1{};
    gkr_field::Fp3 gamma2{};
    gkr_field::Fp3 alpha1{};
    gkr_field::Fp3 alpha2{};

    bool operator==(const FamilyVmLookupChallengesV1& other) const
    {
        return gkr_field::Eq(gamma1, other.gamma1) &&
            gkr_field::Eq(gamma2, other.gamma2) &&
            gkr_field::Eq(alpha1, other.alpha1) &&
            gkr_field::Eq(alpha2, other.alpha2);
    }
};

/**
 * Consensus-facing statement for one unsegmented vertical family proof.
 * `phase0_row_group_root` is the exact ordered MainTrace root and is fixed
 * before the four lookup challenges. It commits the source table, the
 * canonical row/program/pc schedule, every fetched instruction, every SSA
 * value and the terminal residual column. Only lookup inverse/accumulator
 * columns occur in the post-R0 AuxiliaryTrace group.
 */
struct FamilyVmPublicInputsV1 {
    uint16_t version{kFamilyVmPlanVersionV1};
    uint32_t program_id{0};
    /** Consensus-owned registry root selecting program_id. */
    uint256 program_registry_alg_root{};
    uint256 public_statement_binding{};
    uint256 program_table_commitment{};
    alg_hash::Digest program_table_alg_hash{};
    uint256 schedule_commitment{};
    uint256 phase0_row_group_root{};
    uint32_t original_trace_rows{0};
    uint32_t vertical_trace_rows{0};
    uint32_t vm_columns{kFamilyVmExecutableColumnsV1};

    bool operator==(const FamilyVmPublicInputsV1&) const = default;
};

struct FamilyVmProofV1 {
    uint16_t version{kFamilyVmPlanVersionV1};
    FamilyVmLookupChallengesV1 lookup_challenges{};
    air_quotient::AirQuotientSplitRapRowsProof split_rap;
};

inline constexpr uint32_t kFamilyVmProofMagicV1 =
    0x31564d46U; // 'FMV1'
inline constexpr size_t kFamilyVmMaxProofBytesV1 =
    air_quotient::
        kAirQuotientSplitRapRowsMaxProofBytesHard +
    128;

[[nodiscard]] size_t SerializeFamilyVmProofV1(
    const FamilyVmProofV1& proof,
    std::vector<unsigned char>& out);
[[nodiscard]] std::optional<FamilyVmProofV1>
DeserializeFamilyVmProofV1(
    const std::vector<unsigned char>& bytes);

struct FamilyVmProveResultV1 {
    FamilyVmPublicInputsV1 public_inputs{};
    FamilyVmProofV1 proof{};
    bool ok{false};
    std::string note;
};

struct FamilyVmVerificationAuditV1 {
    uint32_t original_trace_rows{0};
    uint32_t vertical_trace_rows{0};
    uint32_t programs{0};
    uint64_t instruction_rows{0};
    bool canonical_program_table_root_pinned{false};
    bool program_selection_bound_in_transcript{false};
    bool registry_membership_proved{false};
    bool exact_row_program_pc_schedule{false};
    bool program_fetch_metadata_logup_pinned{false};
    bool source_multiplicity_consensus_u32{false};
    bool register_multiplicity_consensus_u32{false};
    bool cyclic_current_next_all_rows{false};
    bool dual_lookup_challenges_after_phase0{false};
    bool phase0_group_root_exact{false};
    bool split_rap_quotient_fri_verified{false};
    uint64_t verifier_work_rows{0};
    uint64_t verifier_work_cells{0};
    bool verifier_rebuilds_full_preprocessed_schedule{false};
    bool sublinear_verifier{false};
    bool unsegmented_residual_fold_required{false};
    bool segmented_family_fold_executable{false};
    bool production_authority_ready{false};
    bool valid{false};
    std::string note;
};

/**
 * Execute the canonical ProgramTable over every source row and prove the
 * complete fixed-width VM trace. `source_columns` is column-major and must
 * exactly match table.current_width × original_trace_rows.
 */
[[nodiscard]] FamilyVmProveResultV1 ProveFamilyVmV1(
    const cb::ProgramTable& table,
    const std::vector<std::vector<gkr_field::Fp3>>& source_columns,
    uint32_t program_id,
    const uint256& program_registry_alg_root,
    const uint256& public_statement_binding,
    const uint256& public_fs_seed);

[[nodiscard]] FamilyVmVerificationAuditV1 VerifyFamilyVmV1(
    const cb::ProgramTable& table,
    const FamilyVmPublicInputsV1& public_inputs,
    const FamilyVmProofV1& proof,
    const uint256& public_fs_seed);

/** Consensus must resolve (registry_root, program_id) before verification;
 * accepting a caller-supplied table under an arbitrary non-null registry
 * root is not a production authority path. */
using FamilyVmProgramResolverV1 = std::function<bool(
    const uint256& registry_root,
    uint32_t program_id,
    cb::ProgramTable& selected)>;

[[nodiscard]] FamilyVmVerificationAuditV1
VerifyFamilyVmResolvedV1(
    const FamilyVmPublicInputsV1& public_inputs,
    const FamilyVmProofV1& proof,
    const uint256& public_fs_seed,
    const FamilyVmProgramResolverV1& resolver);

struct FamilyVmVerifierWorkEstimateV1 {
    uint64_t vertical_trace_rows{0};
    uint64_t verifier_work_rows{0};
    uint64_t verifier_work_cells{0};
    bool materializes_vertical_schedule{false};
    bool asymptotically_sublinear{false};
    bool valid{false};
};

[[nodiscard]] FamilyVmVerifierWorkEstimateV1
EstimateFamilyVmVerifierWorkV1(
    const cb::ProgramTable& table,
    uint32_t original_trace_rows);

} // namespace matmul::v4::rc::stage3_family_vm

#endif // BTX_MATMUL_MATMUL_V4_RC_STAGE3_FAMILY_VM_H
