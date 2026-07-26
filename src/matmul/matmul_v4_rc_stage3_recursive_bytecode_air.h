// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BTX_MATMUL_MATMUL_V4_RC_STAGE3_RECURSIVE_BYTECODE_AIR_H
#define BTX_MATMUL_MATMUL_V4_RC_STAGE3_RECURSIVE_BYTECODE_AIR_H

#include <matmul/matmul_v4_rc_stage3_constraint_bytecode.h>

#include <cstdint>
#include <string>
#include <vector>

namespace matmul::v4::rc::recursive_bytecode_air {

namespace aq = air_quotient;
namespace cb = constraint_bytecode;
namespace gf = gkr_field;

inline constexpr uint16_t kRecursiveBytecodeAirVersionV1 = 1;

/**
 * Proof/hash-chip owned operands for one quotient evaluation point.
 *
 * The current opening is at `evaluation_point`; the next opening is at
 * `next_evaluation_point = trace_omega * evaluation_point`.
 * `quotient_opening` is the proof-owned quotient value at the same point.
 * Selectors and the weighted residual are derived inside the AIR.
 */
struct QuotientOpeningRowV1 {
    std::vector<gf::Fp3> current;
    std::vector<gf::Fp3> next;
    gf::Fp3 constraint_lambda{};
    uint32_t query_index{0};
    gf::Fp3 evaluation_point{};
    gf::Fp3 next_evaluation_point{};
    gf::Fp3 quotient_opening{};
};

struct QuotientDomainV1 {
    uint32_t trace_rows{0};
    gf::Fp3 trace_omega{};
    uint32_t evaluation_rows{0};
    gf::Fp3 evaluation_omega{};
    gf::Fp3 coset_shift{};
};

/**
 * Constant-schema SSA interpreter AIR for a caller-selected ProgramTable.
 *
 * The source and interpreter operands occupy disjoint columns and are tied by
 * explicit equality constraints. Every SSA instruction has a witness
 * register and an opcode-specific equation. Program terminals are folded
 * with successive powers of constraint_lambda and constrained equal to the
 * proof-owned quotient residual.
 *
 * The width is table-dependent in V1. This is an executable relation chip,
 * not yet the universal constant-width recursive fixed point.
 */
struct CanonicalBytecodeQuotientAirV1 {
    uint16_t version{kRecursiveBytecodeAirVersionV1};
    uint32_t semantic_rows{0};
    uint32_t air_rows{0};
    uint32_t columns{0};
    uint32_t constraints{0};
    uint32_t instruction_registers{0};
    uint32_t source_current_base{0};
    uint32_t source_next_base{0};
    uint32_t source_lambda{0};
    uint32_t source_query_index{0};
    uint32_t source_evaluation_point{0};
    uint32_t source_next_evaluation_point{0};
    uint32_t source_quotient_opening{0};
    uint32_t interpreter_current_base{0};
    uint32_t interpreter_next_base{0};
    uint32_t interpreter_selector_base{0};
    uint32_t interpreter_lambda{0};
    uint32_t query_bit_base{0};
    uint32_t query_bit_count{0};
    uint32_t query_power_accumulator_base{0};
    uint32_t evaluation_power_base{0};
    uint32_t evaluation_power_count{0};
    uint32_t vanishing{0};
    uint32_t first_denominator_inverse{0};
    uint32_t last_denominator_inverse{0};
    uint32_t register_base{0};
    uint32_t terminal_base{0};
    uint32_t lambda_power_base{0};
    uint32_t weighted_residual{0};
    uint32_t active{0};
    alg_hash::Digest program_key{};
    aq::AirConstraintSystem<gf::Fp3> cs;
    std::vector<std::vector<gf::Fp3>> witness;
    bool caller_selected_program_key{false};
    bool current_next_direct_aliases{false};
    bool selectors_derived_from_evaluation_point{false};
    bool lambda_direct_alias{false};
    bool next_opening_point_is_omega_z{false};
    bool quotient_vanishing_identity_constrained{false};
    /** False until a copy/lookup bus sources these columns from the
     * authenticated PCS/Merkle verifier outputs in the four-slot parent. */
    bool proof_sources_authenticated_by_parent{false};
    bool current_next_values_bound_to_pcs_openings{false};
    bool query_index_to_evaluation_point_in_air{false};
    bool canonical_ssa_executes{false};
    bool terminals_feed_quotient_residual{false};
    bool padding_zero_constrained{false};
    bool constant_width_universal{false};
    bool recursive_fixed_point{false};
    bool authority{false};
    bool valid{false};
    std::string note;
};

[[nodiscard]] CanonicalBytecodeQuotientAirV1
BuildCanonicalBytecodeQuotientAirV1(
    const cb::ProgramTable& table,
    const alg_hash::Digest& selected_program_key,
    const QuotientDomainV1& domain,
    const std::vector<QuotientOpeningRowV1>& rows);

[[nodiscard]] bool ValidateCanonicalBytecodeQuotientAirV1(
    const cb::ProgramTable& table,
    const alg_hash::Digest& selected_program_key,
    const QuotientDomainV1& domain,
    const std::vector<QuotientOpeningRowV1>& rows,
    const CanonicalBytecodeQuotientAirV1& candidate,
    std::string* why = nullptr);

} // namespace matmul::v4::rc::recursive_bytecode_air

#endif // BTX_MATMUL_MATMUL_V4_RC_STAGE3_RECURSIVE_BYTECODE_AIR_H
