// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BTX_MATMUL_MATMUL_V4_RC_STAGE3_MULTIROW_V11_NORMALIZED_PROGRAM_H
#define BTX_MATMUL_MATMUL_V4_RC_STAGE3_MULTIROW_V11_NORMALIZED_PROGRAM_H

#include <matmul/matmul_v4_rc_stage3_constraint_bytecode.h>
#include <matmul/matmul_v4_rc_stage3_multirow_v11_parent_join.h>

#include <cstdint>
#include <string>

namespace matmul::v4::rc::stage3_multirow_v11_normalized_program {

namespace cb = constraint_bytecode;
namespace gf = gkr_field;
namespace pj = stage3_multirow_v11_parent_join;

inline constexpr uint16_t kNormalizedProgramVersionV1 = 1;
inline constexpr uint32_t kPoseidonProgramsV1 = 472;
inline constexpr uint32_t kTranscriptGlueProgramsV1 = 42;
inline constexpr uint32_t kParentJoinProgramsV1 = 762;
inline constexpr uint32_t kExpectedProgramsV1 =
    kPoseidonProgramsV1 +
    kTranscriptGlueProgramsV1 +
    kParentJoinProgramsV1;
inline constexpr uint32_t kFixedPointInstructionCapV1 = 4160;
inline constexpr uint32_t kVerifierShardQueriesV1 = 64;
inline constexpr uint32_t kTraceRowsCapV1 = 1U << 20;
inline constexpr uint32_t kLdeRowsCapV1 = 1U << 24;
inline constexpr uint32_t kFriBlowupV1 = 16;

enum ResidualV1 : uint32_t {
    kResidualProgramShape = 1U << 0,
    kResidualNoncanonicalFieldEncoding = 1U << 1,
    kResidualUnloweredRelation = 1U << 2,
    kResidualFixedPointInstructionCap = 1U << 3,
    kResidualDifferentialAudit = 1U << 4,
};

struct ManifestV1 {
    uint32_t current_columns{0};
    uint32_t next_columns{0};
    uint32_t program_count{0};
    uint64_t instruction_count{0};
    uint64_t poseidon_instructions{0};
    uint64_t transcript_glue_instructions{0};
    uint64_t parent_join_instructions{0};
    uint32_t max_program_instructions{0};
    uint64_t serialized_bytes{0};
    uint32_t poseidon_programs{0};
    uint32_t transcript_glue_programs{0};
    uint32_t parent_join_programs{0};
    uint32_t unlowered_relations{0};
    uint32_t fixedpoint_instruction_cap{
        kFixedPointInstructionCapV1};
    uint32_t query_count{kVerifierShardQueriesV1};
    uint64_t exact_vm_real_rows{0};
    uint32_t exact_vm_trace_rows{0};
    uint64_t exact_vm_lde_rows{0};
    uint32_t residual_mask{0};
    alg_hash::Digest program_root{};
    bool canonical_program_table{false};
    bool canonical_field_encodings{false};
    bool opcode_and_operand_bounds{false};
    bool exact_native_constraint_order{false};
    bool no_opaque_callbacks{false};
    bool instruction_cap_fits{false};
    bool trace_rows_fit{false};
    bool lde_rows_fit{false};
    bool canonical_program_executable{false};
    bool recursive_authority_ready{false};
    std::string note;
};

/**
 * Lower the complete 1,276-constraint V11 parent/transcript relation into the
 * consensus-canonical SSA instruction set.  This is an exact relation
 * migration, not a structural stub: every native constraint has one program
 * in the identical order.
 *
 * The resulting table deliberately remains fail-closed if its exact
 * instruction count exceeds the V11 Q64 fixed-point VM cap.
 */
[[nodiscard]] bool BuildCanonicalProgramTableV1(
    cb::ProgramTable& out,
    ManifestV1* manifest = nullptr,
    std::string* why = nullptr);

/**
 * Strict validation used by the normalized verifier.  In addition to the
 * generic bytecode validator it rejects raw Goldilocks aliases (x+p) before
 * serialization, checks the exact V11 shape/order, and recomputes the exact
 * instruction inventory and AlgHash root.
 */
[[nodiscard]] ManifestV1 AssessProgramTableV1(
    const cb::ProgramTable& table,
    uint32_t instruction_cap = kFixedPointInstructionCapV1);

[[nodiscard]] bool ProgramRootMatchesV1(
    const cb::ProgramTable& table,
    const alg_hash::Digest& expected_root);

struct DifferentialAuditV1 {
    uint32_t native_constraints{0};
    uint32_t bytecode_programs{0};
    uint32_t probes{0};
    uint64_t evaluations{0};
    uint64_t mismatches{0};
    bool product_shape_exact{false};
    bool every_native_constraint_lowered{false};
    bool bit_exact{false};
    bool valid{false};
    std::string note;
};

/**
 * Compare every lowered program against the corresponding real native
 * callback on deterministic full-width Fp3 rows.  This audit does not accept
 * a host verifier bit and does not change any authority gate.
 */
[[nodiscard]] DifferentialAuditV1 AuditAgainstNativeV1(
    const pj::ProductV1& product,
    const cb::ProgramTable& table,
    uint32_t probes = 3);

inline constexpr bool kCanonicalNormalizedVerifierProgramReadyV1 = false;
inline constexpr bool kRecursiveAuthorityReadyV1 = false;
static_assert(!kCanonicalNormalizedVerifierProgramReadyV1);
static_assert(!kRecursiveAuthorityReadyV1);

} // namespace matmul::v4::rc::stage3_multirow_v11_normalized_program

#endif
