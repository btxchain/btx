// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BTX_MATMUL_MATMUL_V4_RC_STAGE3_V13_FIXEDPOINT_BYTECODE_COVERAGE_H
#define BTX_MATMUL_MATMUL_V4_RC_STAGE3_V13_FIXEDPOINT_BYTECODE_COVERAGE_H

#include <matmul/matmul_v4_rc_air_quotient.h>
#include <matmul/matmul_v4_rc_stage3_constraint_bytecode.h>

#include <cstdint>
#include <string>
#include <vector>

namespace matmul::v4::rc::stage3_v13_fixedpoint_bytecode_coverage {

namespace aq = air_quotient;
namespace cb = constraint_bytecode;
namespace gf = gkr_field;

inline constexpr uint16_t kVersionV1 = 1;

/**
 * Fail-closed inventory of the arity-two V13 verifier callback graph.
 *
 * A constraint counts as recursively executable only when it came from the
 * consensus-canonical bytecode adapter.  A known native family is classified
 * for migration planning but never promoted to bytecode merely because a
 * semantically similar V11 chip exists.  This distinction prevents an outer
 * acceptance-only ProgramTable from being mistaken for a complete recursive
 * verifier.
 */
struct CallbackCoverageV1 {
    uint16_t version{kVersionV1};
    uint32_t rows{0};
    uint32_t columns{0};
    uint32_t constraints{0};
    /**
     * Constraints carrying the bytecode adapter's diagnostic name.  The name
     * is not statement data and is therefore not accepted as provenance
     * after a native callback relocation.
     */
    uint32_t bytecode_adapter_named_constraints{0};
    /**
     * Constraints reconstructed by the canonical ProgramTable adapter and
     * carrying both its committed table root and exact constraint ordinal.
     * This is counted independently of the diagnostic constraint name.
     */
    uint32_t canonical_program_provenance_constraints{0};
    /**
     * Constraints with only one half of the root/ordinal provenance pair.
     * Such a constraint is always unproved and makes the audit fail closed.
     */
    uint32_t invalid_program_provenance_constraints{0};
    uint32_t canonical_program_roots{0};
    /**
     * Canonical proof-tape constraints recognized from the committed
     * ProgramTable bytes after undoing a parent-column relocation.  The
     * diagnostic constraint name is deliberately not consulted.
     */
    uint32_t canonical_tape_constraints{0};
    uint32_t canonical_tape_program_tables{0};
    /**
     * Number of recognized tape tables for which every canonical constraint
     * ordinal occurs exactly once.  A truncated or duplicated tape therefore
     * cannot satisfy the tape-family inventory.
     */
    uint32_t complete_canonical_tape_program_tables{0};
    bool canonical_tape_inventory_complete{false};
    uint32_t native_lift_constraints{0};
    uint32_t native_poseidon_constraints{0};
    uint32_t native_tape_constraints{0};
    uint32_t native_merkle_fold_constraints{0};
    uint32_t native_deep_constraints{0};
    uint32_t native_alias_constraints{0};
    uint32_t native_acceptance_constraints{0};
    uint32_t unknown_constraints{0};
    uint32_t native_or_unproven_constraints{0};
    uint32_t classified_constraints{0};
    std::vector<std::string> unknown_families;
    bool shape_power_of_two{false};
    bool inventory_complete{false};
    bool all_constraints_canonical_bytecode{false};
    bool whole_parent_program_reentry_ready{false};
    std::string note;
};

[[nodiscard]] CallbackCoverageV1
AssessCallbackCoverageV1(
    const aq::AirConstraintSystem<gf::Fp3>& cs);

/**
 * Existing canonical vertical-verifier bytecode inventory.
 *
 * This report proves only that each phase table is deterministic, valid and
 * challenge-value independent.  It does not claim parity with the horizontal
 * V13 callback graph; that claim remains false until a differential bridge or
 * canonical emission for every residual family is implemented.
 */
struct VerticalProgramCoverageV1 {
    uint16_t version{kVersionV1};
    uint32_t phase_tables{0};
    uint32_t programs{0};
    uint32_t max_current_width{0};
    uint32_t max_next_width{0};
    uint32_t max_challenge_width{0};
    uint64_t serialized_bytes{0};
    std::vector<alg_hash::Digest> phase_roots;
    bool every_table_valid{false};
    bool every_root_nonzero{false};
    bool every_table_challenge_value_independent{false};
    bool canonical_vertical_foundation{false};
    bool horizontal_to_vertical_parity_proven{false};
    bool recursive_reentry_ready{false};
    std::string note;
};

[[nodiscard]] VerticalProgramCoverageV1
AssessCanonicalVerticalProgramsV1();

struct ReentryCoverageV1 {
    CallbackCoverageV1 horizontal{};
    VerticalProgramCoverageV1 vertical{};
    bool acceptance_only_attack_rejected{false};
    bool unknown_family_attack_rejected{false};
    bool exact_callback_to_bytecode_parity{false};
    bool recursive_reentry_ready{false};
    std::string note;
};

[[nodiscard]] ReentryCoverageV1 AssessReentryCoverageV1(
    const aq::AirConstraintSystem<gf::Fp3>& cs);

inline constexpr bool kExecutableRecursiveReentryV1 = false;
inline constexpr bool kAuthorityReadyV1 = false;
static_assert(!kExecutableRecursiveReentryV1);
static_assert(!kAuthorityReadyV1);

} // namespace matmul::v4::rc::stage3_v13_fixedpoint_bytecode_coverage

#endif
