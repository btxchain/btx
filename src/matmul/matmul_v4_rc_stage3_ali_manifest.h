// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BTX_MATMUL_MATMUL_V4_RC_STAGE3_ALI_MANIFEST_H
#define BTX_MATMUL_MATMUL_V4_RC_STAGE3_ALI_MANIFEST_H

#include <matmul/matmul_v4_rc_stage3_constant_width_bytecode_air.h>
#include <matmul/matmul_v4_rc_stage3_production_family_programs.h>

#include <cstdint>
#include <string>
#include <vector>

namespace matmul::v4::rc::stage3_ali_manifest {

namespace ah = alg_hash;
namespace cb = constraint_bytecode;
namespace cw = constant_width_bytecode_air;
namespace rba = recursive_bytecode_air;
namespace sites = soundness_scenarios;
namespace topo = universal_topology;

inline constexpr uint16_t kProductionAliManifestVersionV1 = 1;
inline constexpr uint32_t kProductionAliFamilyCountV1 = 28;
inline constexpr uint32_t kProductionAliQueriesV1 = 192;
inline constexpr uint32_t kProductionAliPaddedQueryRowsV1 = 256;
inline constexpr uint32_t kProductionAliCompiledColumnsV1 = 53;
inline constexpr uint16_t kProductionAliAssessmentVersionV2 = 2;

/**
 * Exact verifier-support inventory for one canonical production family.
 *
 * All values are recomputed from the source ProgramTable and the compiled
 * constant-width quotient program.  No count, key, degree, row bound, or
 * domain size is accepted as a readiness literal.
 */
struct ProductionAliFamilyV1 {
    uint32_t family_index{0};
    sites::ProductionProofSiteKind kind{};
    RCStage3RelationRole role{};
    std::vector<uint16_t> semantic_endpoints;
    bool semantic_relation_complete{false};

    ah::Digest source_program_key{};
    uint32_t source_current_width{0};
    uint32_t source_next_width{0};
    uint32_t source_challenge_width{0};
    uint32_t source_constraint_count{0};
    uint32_t source_instruction_count{0};
    uint32_t source_challenge_loads{0};
    uint32_t source_max_degree{0};
    uint64_t source_max_composed_degree{0};
    uint32_t source_quotient_len{0};
    uint32_t source_n_coeffs{0};
    uint32_t source_n_lde{0};

    ah::Digest compiled_program_key{};
    uint32_t compiled_current_width{0};
    uint32_t compiled_next_width{0};
    uint32_t compiled_challenge_width{0};
    uint32_t compiled_constraint_count{0};
    uint32_t compiled_instruction_count{0};
    uint32_t compiled_challenge_loads{0};
    uint32_t compiled_max_degree{0};
    uint64_t compiled_max_composed_degree{0};
    uint32_t compiled_quotient_len{0};
    uint32_t compiled_n_coeffs{0};
    uint32_t compiled_n_lde{0};
    uint32_t compiled_physical_columns{0};

    uint32_t semantic_rows{0};
    uint32_t padded_source_rows{0};
    uint64_t vertical_logical_rows{0};
    uint64_t vertical_padded_rows{0};
    uint64_t coefficient_cap{0};
    uint32_t minimum_vm_segments{0};

    bool source_table_canonical{false};
    bool source_table_non_stub{false};
    bool challenge_class_degree_checked{false};
    bool compiled_table_canonical{false};
    bool exact_q192_rows{false};
    bool quotient_and_lde_bounds_derived{false};
    bool within_coefficient_cap{false};
    bool constant_width_53{false};

    bool operator==(const ProductionAliFamilyV1&) const = default;
};

struct ProductionAliManifestV1 {
    uint16_t version{kProductionAliManifestVersionV1};
    std::vector<ProductionAliFamilyV1> families;
    ah::Digest commitment{};

    uint32_t maximum_source_width{0};
    uint32_t maximum_source_challenge_width{0};
    uint32_t maximum_source_constraints{0};
    uint32_t maximum_source_instructions{0};
    uint32_t maximum_source_degree{0};
    uint32_t maximum_source_quotient_len{0};
    uint32_t maximum_source_n_lde{0};
    uint32_t maximum_compiled_constraints{0};
    uint32_t maximum_compiled_instructions{0};
    uint32_t maximum_compiled_degree{0};
    uint32_t maximum_compiled_quotient_len{0};
    uint32_t maximum_compiled_n_lde{0};
    uint64_t maximum_vertical_logical_rows{0};
    uint64_t maximum_vertical_padded_rows{0};
    uint32_t maximum_minimum_vm_segments{0};
    uint64_t total_source_constraints{0};
    uint64_t total_source_instructions{0};
    uint64_t total_compiled_constraints{0};
    uint64_t total_compiled_instructions{0};
    uint32_t semantic_complete_families{0};
    uint32_t semantic_partial_families{0};
    uint32_t families_with_challenge_loads{0};

    bool exact_28_family_order{false};
    bool every_source_key_derived{false};
    bool every_compiled_key_derived{false};
    bool every_source_non_stub{false};
    bool every_challenge_degree_checked{false};
    bool every_q192_row_bound_exact{false};
    bool every_quotient_lde_bound_derived{false};
    bool every_compiled_program_53_columns{false};
    bool every_family_within_cap{false};
    bool canonical_u32_injective_commitment{false};
    bool local_manifest_complete{false};

    /** Deliberately separate: a local manifest is not recursive execution. */
    bool recursive_root_consumed{false};
    bool production_authority{false};
    std::string note;

    bool operator==(const ProductionAliManifestV1&) const = default;
};

/**
 * Production quotient domain for a source table.  The trace has 256 rows
 * (Q192 plus canonical padding); the LDE size is derived from the table's
 * actual constraint degree and AirConstraintSystem quotient bound.
 */
[[nodiscard]] bool BuildProductionAliSourceDomainV1(
    const cb::ProgramTable& source,
    rba::QuotientDomainV1& out,
    std::string* why = nullptr);

/** Build the exact canonical 28-family inventory. */
[[nodiscard]] ProductionAliManifestV1
BuildProductionAliManifestV1();

/**
 * Hardened derivation entry point for the registered production sources.
 *
 * Unlike BuildProductionAliManifestV1, this accepts an explicit source vector
 * so adversarial tests and registry callers can prove that malformed source
 * sets fail before they become an ALI manifest.  It validates each bytecode
 * table (including opcode/register/degree recomputation), rejects structural
 * stubs, and then requires exact equality to the canonical family registry.
 */
[[nodiscard]] bool BuildProductionAliManifestFromSourcesV1(
    const sites::ProductionProofSiteManifest& site_manifest,
    const std::vector<topo::ProductionFamilyProgramSourceV1>& sources,
    ProductionAliManifestV1& out,
    std::string* why = nullptr);

/**
 * Commitment to the exact ordered inventory.  Every uint64 and every
 * Goldilocks digest limb is encoded as (lo32, hi32); raw x+p field aliases
 * are rejected instead of canonicalized.
 */
[[nodiscard]] ah::Digest
ComputeProductionAliManifestCommitmentV1(
    const ProductionAliManifestV1& manifest);

/** Fail-closed equality to a freshly derived canonical manifest. */
[[nodiscard]] bool ValidateProductionAliManifestV1(
    const ProductionAliManifestV1& manifest,
    std::string* why = nullptr);

/** Per-role aggregation of the exact canonical family bytecode inventory. */
struct ProductionAliRoleAssessmentV2 {
    RCStage3RelationRole role{};
    uint32_t family_count{0};
    uint32_t semantic_complete_families{0};
    uint32_t semantic_partial_families{0};
    uint32_t required_semantic_endpoints{0};
    uint32_t locally_complete_semantic_endpoints{0};
    uint64_t source_constraints{0};
    uint64_t source_instructions{0};
    uint64_t compiled_constraints{0};
    uint64_t compiled_instructions{0};
    uint32_t maximum_source_degree{0};
    uint64_t maximum_source_composed_degree{0};
    uint32_t maximum_source_n_lde{0};
    uint32_t maximum_compiled_degree{0};
    uint64_t maximum_compiled_composed_degree{0};
    uint32_t maximum_compiled_n_lde{0};
    uint32_t residual_obligations_or{0};
    bool every_table_non_stub{false};
    bool every_degree_bound_derived{false};
    /** Every registered family for this role is locally complete. This is
     * weaker than complete endpoint coverage. */
    bool every_family_locally_complete{false};
    /** Every endpoint required by the role is named by a locally complete
     * canonical family, with no partial-family residual. */
    bool complete_endpoint_coverage{false};

    bool operator==(
        const ProductionAliRoleAssessmentV2&) const = default;
};

/**
 * Role-complete view of the V1 family manifest.
 *
 * The existing 28-family ALI manifest proves local bytecode/degree/domain
 * coverage.  V2 makes the semantic distinction impossible to miss: all 14
 * roles have canonical non-stub ProgramTables, but 14 of 28 families remain
 * partial and the locally complete families cover only 14 of 52 required
 * endpoints.  No role therefore has complete semantic endpoint coverage.
 */
struct ProductionAliAssessmentV2 {
    uint16_t version{kProductionAliAssessmentVersionV2};
    ah::Digest family_manifest_commitment{};
    std::vector<ProductionAliRoleAssessmentV2> roles;
    std::vector<topo::ProductionPartialFamilyResidualV1>
        partial_family_residuals;
    uint32_t family_count{0};
    uint32_t role_count{0};
    uint32_t semantic_complete_families{0};
    uint32_t semantic_partial_families{0};
    uint32_t fully_semantic_roles{0};
    uint32_t required_semantic_endpoints{0};
    uint32_t locally_complete_semantic_endpoints{0};
    uint64_t source_constraints{0};
    uint64_t source_instructions{0};
    uint64_t compiled_constraints{0};
    uint64_t compiled_instructions{0};
    bool exact_28_family_registry{false};
    bool exact_14_role_order{false};
    bool every_registered_role_has_program{false};
    bool every_program_table_non_stub{false};
    bool every_degree_bound_derived{false};
    bool local_ali_assessment_complete{false};
    bool semantic_relation_manifest_complete{false};
    bool recursive_root_consumed{false};
    bool production_authority{false};
    std::string note;
    ah::Digest commitment{};

    bool operator==(
        const ProductionAliAssessmentV2&) const = default;
};

[[nodiscard]] bool BuildProductionAliAssessmentFromSourcesV2(
    const sites::ProductionProofSiteManifest& site_manifest,
    const std::vector<topo::ProductionFamilyProgramSourceV1>& sources,
    ProductionAliAssessmentV2& out,
    std::string* why = nullptr);

[[nodiscard]] ProductionAliAssessmentV2
BuildProductionAliAssessmentV2();

[[nodiscard]] ah::Digest
ComputeProductionAliAssessmentCommitmentV2(
    const ProductionAliAssessmentV2& assessment);

[[nodiscard]] bool ValidateProductionAliAssessmentV2(
    const ProductionAliAssessmentV2& assessment,
    std::string* why = nullptr);

inline constexpr bool kProductionAliManifestRecursiveRootConsumedV1 =
    false;
inline constexpr bool kProductionAliManifestAuthorityV1 = false;
static_assert(!kProductionAliManifestRecursiveRootConsumedV1);
static_assert(!kProductionAliManifestAuthorityV1);

} // namespace matmul::v4::rc::stage3_ali_manifest

#endif // BTX_MATMUL_MATMUL_V4_RC_STAGE3_ALI_MANIFEST_H
