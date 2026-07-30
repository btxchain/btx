// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BTX_MATMUL_MATMUL_V4_RC_STAGE3_CONSTANT_WIDTH_BYTECODE_AIR_H
#define BTX_MATMUL_MATMUL_V4_RC_STAGE3_CONSTANT_WIDTH_BYTECODE_AIR_H

#include <matmul/matmul_v4_rc_stage3_family_vm.h>
#include <matmul/matmul_v4_rc_stage3_recursive_bytecode_air.h>

#include <cstdint>
#include <string>
#include <vector>

namespace matmul::v4::rc::constant_width_bytecode_air {

namespace cb = constraint_bytecode;
namespace gf = gkr_field;
namespace rba = recursive_bytecode_air;
namespace vm = stage3_family_vm;

inline constexpr uint16_t
    kConstantWidthBytecodeAirVersionV1 = 1;

/**
 * Canonical source tape for one vertical quotient-verifier program.
 *
 * The table-dependent opening width lives in the number of source-definition
 * rows of FamilyVmV1, not in physical AIR width.  `current_base` and
 * `next_base` are disjoint, so the compiler cannot silently reuse a current
 * opening as a next opening.  The remaining columns are proof data or
 * canonically derived schedule witnesses.
 */
struct SourceLayoutV1 {
    uint32_t current_base{0};
    uint32_t next_base{0};
    uint32_t challenge_base{0};
    uint32_t challenge_width{0};
    uint32_t constraint_lambda{0};
    uint32_t query_index{0};
    uint32_t evaluation_point{0};
    uint32_t next_evaluation_point{0};
    uint32_t quotient_opening{0};
    uint32_t first_denominator_inverse{0};
    uint32_t last_denominator_inverse{0};
    uint32_t semantic_ordinal{0};
    uint32_t active{0};
    uint32_t cut{0};
    uint32_t cut_inverse{0};
    uint32_t query_bit_base{0};
    uint32_t query_bit_count{0};
    uint32_t source_width{0};

    bool operator==(const SourceLayoutV1&) const = default;
};

/**
 * Deterministic compilation result. `compiled_table` is a normal canonical
 * ProgramTable consumed by FamilyVmV1. Its physical proof width is therefore
 * exactly kFamilyVmExecutableColumnsV1 for every supported source table.
 */
struct CompiledQuotientProgramV1 {
    uint16_t version{kConstantWidthBytecodeAirVersionV1};
    SourceLayoutV1 layout{};
    uint32_t semantic_rows{0};
    uint32_t padded_rows{0};
    uint32_t original_programs{0};
    uint32_t original_instructions{0};
    uint32_t compiled_programs{0};
    uint32_t compiled_instructions{0};
    uint32_t physical_columns{0};
    alg_hash::Digest selected_program_key{};
    alg_hash::Digest compiled_program_key{};
    cb::ProgramTable compiled_table{};
    bool challenge_free_source_table{false};
    bool challenge_loads_use_dedicated_tape{false};
    bool challenge_tape_constant_compiled{false};
    bool current_next_sources_disjoint{false};
    bool query_point_derived_from_index{false};
    bool selector_derivation_compiled{false};
    bool terminal_lambda_fold_compiled{false};
    bool quotient_identity_compiled{false};
    bool canonical_padding_schedule_compiled{false};
    bool constant_physical_width{false};
    bool valid{false};
    std::string note;
};

[[nodiscard]] CompiledQuotientProgramV1
CompileConstantWidthQuotientProgramV1(
    const cb::ProgramTable& selected_table,
    const alg_hash::Digest& selected_program_key,
    const rba::QuotientDomainV1& domain,
    uint32_t semantic_rows);

/**
 * Exact capacity inventory for the compiled vertical VM at one semantic
 * query count.  `minimum_vm_segments` is arithmetic only: it does not claim
 * that a segmented proof is executable.  A production segmented backend
 * additionally has to constrain ordered segment roots, boundary machine
 * state and the terminal residual fold.
 */
struct VerticalVmCapacityV1 {
    uint32_t semantic_rows{0};
    uint32_t padded_source_rows{0};
    uint32_t source_columns{0};
    uint32_t compiled_programs{0};
    uint32_t compiled_instructions{0};
    uint32_t physical_columns{0};
    uint64_t logical_vertical_rows{0};
    uint64_t padded_vertical_rows{0};
    uint64_t coefficient_cap{0};
    uint32_t minimum_vm_segments{0};
    bool fits_unsegmented_split_rap{false};
    bool ordered_segment_roots_constrained{false};
    bool boundary_machine_state_constrained{false};
    bool terminal_segment_fold_constrained{false};
    bool segmented_vertical_vm_executable{false};
    bool valid{false};
    std::string note;
};

[[nodiscard]] VerticalVmCapacityV1
AssessVerticalVmCapacityV1(
    const cb::ProgramTable& selected_table,
    const alg_hash::Digest& selected_program_key,
    const rba::QuotientDomainV1& domain,
    uint32_t semantic_rows);

struct PublicInputsV1 {
    uint16_t version{kConstantWidthBytecodeAirVersionV1};
    uint32_t program_id{0};
    uint256 program_registry_alg_root{};
    alg_hash::Digest selected_program_key{};
    alg_hash::Digest compiled_program_key{};
    rba::QuotientDomainV1 domain{};
    SourceLayoutV1 source_layout{};
    uint32_t semantic_rows{0};
    uint32_t padded_rows{0};
    uint32_t physical_columns{0};
    /** Exact R0 row root of source cells, instruction metadata and results. */
    uint256 ordered_vm_phase0_root{};
    vm::FamilyVmPublicInputsV1 family{};
};

struct ProofV1 {
    uint16_t version{kConstantWidthBytecodeAirVersionV1};
    vm::FamilyVmProofV1 family{};
};

/** One quotient opening plus the verifier-owned post-commitment challenge
 * vector used by Challenge opcodes. Every active row must carry the same
 * vector; the vertical program constrains that equality. */
struct OpeningRowV1 {
    rba::QuotientOpeningRowV1 quotient{};
    std::vector<gf::Fp3> verifier_challenges;
};

struct ProveResultV1 {
    PublicInputsV1 public_inputs{};
    ProofV1 proof{};
    bool ok{false};
    std::string note;
};

struct VerificationAuditV1 {
    uint32_t semantic_rows{0};
    uint32_t padded_rows{0};
    uint32_t original_programs{0};
    uint32_t original_instructions{0};
    uint32_t compiled_instructions{0};
    uint32_t physical_columns{0};
    uint64_t verifier_work_rows{0};
    uint64_t verifier_work_cells{0};
    bool caller_selected_program_key{false};
    bool compiled_program_key_canonical{false};
    bool current_next_source_cells_disjoint{false};
    bool query_index_to_evaluation_point_in_vm{false};
    bool selector_derivation_in_vm{false};
    bool terminal_lambda_fold_in_vm{false};
    bool quotient_vanishing_identity_in_vm{false};
    bool canonical_padding_schedule_in_vm{false};
    bool ordered_vm_phase0_root_exact{false};
    bool split_rap_quotient_fri_verified{false};
    bool constant_width_universal{false};
    bool registry_membership_proved{false};
    bool challenge_loads_from_dedicated_tape{false};
    bool challenge_tape_constant_across_active_rows{false};
    bool challenge_tape_owned_by_parent_fs{false};
    bool segmented_vertical_vm_executable{false};
    /**
     * Deliberate residuals. The VM authenticates its own ordered source tape,
     * but the normalized parent does not yet equality-link that R0 root/cells
     * to the child PCS verifier exports.
     */
    bool source_cells_owned_by_parent_pcs{false};
    bool query_schedule_owned_by_parent_fs{false};
    bool recursive_parent_consumes_this_verifier{false};
    bool recursive_fixed_point{false};
    bool production_authority_ready{false};
    bool valid{false};
    std::string note;
};

[[nodiscard]] ProveResultV1
ProveConstantWidthBytecodeQuotientV1(
    const cb::ProgramTable& selected_table,
    const alg_hash::Digest& selected_program_key,
    const rba::QuotientDomainV1& domain,
    const std::vector<rba::QuotientOpeningRowV1>& rows,
    uint32_t program_id,
    const uint256& program_registry_alg_root,
    const uint256& public_fs_seed);

[[nodiscard]] ProveResultV1
ProveConstantWidthBytecodeQuotientV1(
    const cb::ProgramTable& selected_table,
    const alg_hash::Digest& selected_program_key,
    const rba::QuotientDomainV1& domain,
    const std::vector<OpeningRowV1>& rows,
    uint32_t program_id,
    const uint256& program_registry_alg_root,
    const uint256& public_fs_seed);

[[nodiscard]] VerificationAuditV1
VerifyConstantWidthBytecodeQuotientV1(
    const cb::ProgramTable& selected_table,
    const PublicInputsV1& public_inputs,
    const ProofV1& proof,
    const uint256& public_fs_seed);

} // namespace matmul::v4::rc::constant_width_bytecode_air

#endif // BTX_MATMUL_MATMUL_V4_RC_STAGE3_CONSTANT_WIDTH_BYTECODE_AIR_H
