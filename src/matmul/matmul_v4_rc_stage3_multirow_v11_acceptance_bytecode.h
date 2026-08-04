// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BTX_MATMUL_MATMUL_V4_RC_STAGE3_MULTIROW_V11_ACCEPTANCE_BYTECODE_H
#define BTX_MATMUL_MATMUL_V4_RC_STAGE3_MULTIROW_V11_ACCEPTANCE_BYTECODE_H

#include <matmul/matmul_v4_rc_stage3_constraint_bytecode.h>
#include <matmul/matmul_v4_rc_stage3_multirow_v11_recursive_parent.h>
#include <matmul/matmul_v4_rc_stage3_universal_topology.h>

#include <array>
#include <cstdint>
#include <string>
#include <vector>

namespace matmul::v4::rc::
stage3_multirow_v11_acceptance_bytecode {

namespace aq = air_quotient;
namespace cb = constraint_bytecode;
namespace gf = gkr_field;
namespace rp = stage3_multirow_v11_recursive_parent;
namespace ut = universal_topology;

inline constexpr uint16_t kAcceptanceBytecodeVersionV1 = 1;
inline constexpr uint32_t kAcceptanceSemanticColumnsV1 = 74;
inline constexpr uint32_t kAcceptanceProofColumnsV1 = 75;
inline constexpr uint32_t kAcceptanceStructuralConstraintsV1 = 10;
inline constexpr uint32_t kAcceptancePinConstraintsPerColumnV1 = 3;
inline constexpr uint32_t kAcceptanceDependentConstraintsV1 = 1;
inline constexpr uint32_t kAcceptanceConstraintCountV1 =
    kAcceptanceStructuralConstraintsV1 +
    kAcceptanceDependentConstraintsV1;
inline constexpr uint32_t kAcceptanceLegacyPinConstraintCountV1 =
    kAcceptanceSemanticColumnsV1 *
    kAcceptancePinConstraintsPerColumnV1;
inline constexpr uint32_t kAcceptanceLegacyFullConstraintCountV1 =
    kAcceptanceConstraintCountV1 +
    kAcceptanceLegacyPinConstraintCountV1;

/**
 * Exact V2 acceptance instance split along its trust boundary.
 *
 * `structural_cs` is the static 10-equation schedule relation plus the
 * dependent-zero equation. `legacy_full_callback_cs` additionally contains
 * the 222 statement-specific first/second/padding pins retained by the
 * callback implementation. Those 222 equations are not bytecode: SAFE
 * FixedTrace V3 verifier-pins all 74 semantic columns, in order, to the
 * statement-owned acceptance row root.
 */
struct AcceptanceInstanceV1 {
    uint16_t version{kAcceptanceBytecodeVersionV1};
    rp::LayoutV1 layout{};
    std::array<gf::Fp3, kAcceptanceSemanticColumnsV1> first_row{};
    std::array<gf::Fp3, kAcceptanceSemanticColumnsV1> second_row{};
    aq::AirConstraintSystem<gf::Fp3> structural_cs{};
    aq::AirConstraintSystem<gf::Fp3> legacy_full_callback_cs{};
    std::vector<std::vector<gf::Fp3>> columns;
    std::vector<uint32_t> fixed_trace_columns;
    uint256 fixed_trace_manifest_root{};
    uint256 fixed_trace_row_root{};
    uint256 parent_statement_root{};
    bool exact_v2_shape{false};
    bool dependent_zero_column_constrained{false};
    bool valid{false};
    std::string note;
};

/**
 * Build a complete 256-row instance with rows 0/1 supplied and all padding
 * rows zero. The returned callbacks are independently authored reference
 * equations, not callbacks generated from bytecode.
 */
[[nodiscard]] AcceptanceInstanceV1 BuildAcceptanceInstanceV1(
    const std::array<gf::Fp3, kAcceptanceSemanticColumnsV1>& first_row,
    const std::array<gf::Fp3, kAcceptanceSemanticColumnsV1>& second_row,
    const uint256& parent_statement_root);

/**
 * Build the statement-independent table in exact order:
 *   10 schedule relations, then 1 dependent-zero relation.
 */
[[nodiscard]] bool BuildCanonicalProgramTableV1(
    const AcceptanceInstanceV1& instance,
    cb::ProgramTable& out,
    std::string* why = nullptr);

struct ProgramBindingV1 {
    uint16_t version{kAcceptanceBytecodeVersionV1};
    cb::ProgramTable table{};
    cb::ProgramTableCommitmentPair table_commitment{};
    uint256 fixed_trace_manifest_root{};
    uint256 parent_statement_root{};
    uint256 bound_external_root{};
    alg_hash::Digest bound_recursive_root{};
    uint32_t residual_mask{0};
    bool exact_program_table{false};
    bool exact_callback_order{false};
    bool fixed_manifest_version_shape_bound{false};
    bool statement_independent_program{false};
    bool fixed_trace_pin_redundancy_proved{false};
    bool canonical_bytecode_residual_removable{false};
    bool consensus_registry_bound{false};
    bool canonical_bytecode_complete{false};
    bool valid{false};
    std::string note;
};

enum BindingResidualV1 : uint32_t {
    /** The V2 statement's program-registry root is deliberately still null. */
    kResidualConsensusRegistryRoot = 1U << 0,
};

[[nodiscard]] ProgramBindingV1 BuildProgramBindingV1(
    const AcceptanceInstanceV1& instance);

struct DifferentialAuditV1 {
    uint32_t callback_constraints{0};
    uint32_t bytecode_programs{0};
    uint32_t honest_rows{0};
    uint32_t adversarial_probes{0};
    uint64_t evaluations{0};
    uint64_t mismatches{0};
    bool shape_and_order_exact{false};
    bool honest_rows_bit_exact{false};
    bool adversarial_rows_bit_exact{false};
    bool valid{false};
    std::string note;
};

/**
 * Execute every static structural callback and corresponding SSA program on
 * all 256 honest row pairs plus deterministic full-width adversarial probes.
 */
[[nodiscard]] DifferentialAuditV1 AuditAgainstCallbacksV1(
    const AcceptanceInstanceV1& instance,
    const cb::ProgramTable& table,
    uint32_t adversarial_probes = 8);

/**
 * Machine-checked decomposition lemma for the 233-equation legacy callback:
 *
 *   FixedTrace(all 74 semantic columns, ordered, row root)
 *       AND StaticAcceptance(11 equations)
 *       ==> LegacyAcceptance(233 equations).
 *
 * It also exhibits mutations in each pin family which the legacy equation
 * rejects and whose recomputed FixedTrace row root differs.
 */
struct FixedTraceRedundancyAuditV1 {
    uint32_t structural_constraints{0};
    uint32_t legacy_pin_constraints{0};
    uint32_t legacy_full_constraints{0};
    uint32_t covered_semantic_columns{0};
    uint32_t covered_trace_rows{0};
    uint32_t pin_family_mutations_tested{0};
    uint32_t pin_family_mutations_rejected{0};
    bool exact_ordered_fixed_trace_coverage{false};
    bool fixed_trace_root_recomputed{false};
    bool statement_owns_fixed_trace_root{false};
    bool structural_trace_accepts{false};
    bool legacy_full_trace_accepts{false};
    bool every_pin_equation_redundant_under_fixed_trace{false};
    bool no_full_callback_equation_nonredundant{false};
    bool valid{false};
    std::string note;
};

[[nodiscard]] FixedTraceRedundancyAuditV1
AuditFixedTracePinRedundancyV1(
    const AcceptanceInstanceV1& instance);

/**
 * Strict equality to a freshly rebuilt canonical table plus differential
 * execution. Generic `ValidateProgramTable` alone is intentionally
 * insufficient because it accepts semantically empty one-column stubs.
 */
[[nodiscard]] ProgramBindingV1 AssessCanonicalProgramV1(
    const AcceptanceInstanceV1& instance,
    const cb::ProgramTable& candidate,
    uint32_t adversarial_probes = 8);

enum class RegistrySlotV1 : uint8_t {
    UniversalParentVerifier = 1,
};

/**
 * Precise interface for the current immutable registry schema.
 *
 * `raw_table_membership_proved` can become true only when a caller supplies a
 * nonzero consensus-expected registry AlgHash and the registry is recomputed
 * under that root. The canonical table is static and compatible with the
 * existing universal-parent registry slot. Production remains false while
 * the consensus registry root is absent.
 */
struct RegistryMembershipAssessmentV1 {
    uint16_t version{kAcceptanceBytecodeVersionV1};
    RegistrySlotV1 slot{RegistrySlotV1::UniversalParentVerifier};
    alg_hash::Digest expected_consensus_registry_root{};
    alg_hash::Digest recomputed_registry_root{};
    cb::ProgramTableCommitmentPair expected_program_leaf{};
    uint32_t expected_columns{kAcceptanceProofColumnsV1};
    bool consensus_root_supplied{false};
    bool registry_root_recomputed{false};
    bool registry_root_matches_consensus{false};
    bool exact_program_leaf_matches{false};
    bool exact_width_matches{false};
    bool current_schema_binds_fixed_manifest{false};
    bool static_program_schema_compatible{false};
    bool raw_table_membership_proved{false};
    bool bound_program_membership_proved{false};
    bool production_authority{false};
    std::string note;
};

[[nodiscard]] RegistryMembershipAssessmentV1
AssessRegistryMembershipV1(
    const ProgramBindingV1& binding,
    const ut::ProductionProgramRegistryV1& registry,
    const alg_hash::Digest& expected_consensus_registry_root);

inline constexpr bool kAcceptanceCanonicalBytecodeExecutableV1 = true;
inline constexpr bool
    kAcceptanceCanonicalBytecodeResidualRemovableV1 = true;
inline constexpr bool kAcceptanceConsensusRegistryBoundV1 = false;
inline constexpr bool kAcceptanceProductionAuthorityV1 = false;
static_assert(kAcceptanceCanonicalBytecodeExecutableV1);
static_assert(kAcceptanceCanonicalBytecodeResidualRemovableV1);
static_assert(!kAcceptanceConsensusRegistryBoundV1);
static_assert(!kAcceptanceProductionAuthorityV1);

} // namespace matmul::v4::rc::
  // stage3_multirow_v11_acceptance_bytecode

#endif
