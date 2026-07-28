// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/MIT.

#ifndef BTX_MATMUL_MATMUL_V4_RC_STAGE3_PRODUCTION_CANONICAL_REGISTRY_H
#define BTX_MATMUL_MATMUL_V4_RC_STAGE3_PRODUCTION_CANONICAL_REGISTRY_H

#include <matmul/matmul_v4_rc_stage3_multirow_v11_acceptance_bytecode.h>
#include <matmul/matmul_v4_rc_stage3_multirow_v11_normalized_program.h>
#include <matmul/matmul_v4_rc_stage3_production_family_programs.h>

#include <cstdint>
#include <string>
#include <vector>

namespace matmul::v4::rc::production_canonical_registry {

namespace av =
    stage3_multirow_v11_acceptance_bytecode;
namespace np =
    stage3_multirow_v11_normalized_program;
namespace sites = soundness_scenarios;
namespace sched = aggregation_scheduler;
namespace ut = universal_topology;
namespace cb = constraint_bytecode;

inline constexpr uint16_t kCanonicalRegistryBuilderVersionV1 = 1;

enum ResidualV1 : uint32_t {
    kResidualManifestOrSchedule = 1U << 0,
    kResidualCanonicalFamilySources = 1U << 1,
    kResidualIncompleteFamilySemantics = 1U << 2,
    kResidualAcceptanceProgram = 1U << 3,
    kResidualNormalizedProgram = 1U << 4,
    kResidualNormalizedProgramExecution = 1U << 5,
    kResidualParentProgramRootReconstruction = 1U << 6,
    kResidualRegistryRootReconstruction = 1U << 7,
};

/**
 * One exact, ordered production-family residual.  A missing-obligations mask
 * of zero is forbidden for an incomplete family.
 */
struct FamilySemanticResidualV1 {
    uint32_t family_index{0};
    sites::ProductionProofSiteKind kind{};
    RCStage3RelationRole role{};
    uint32_t missing_obligations{0};

    bool operator==(const FamilySemanticResidualV1&) const = default;
};

/**
 * Fail-closed assessment of the immutable production registry inputs.
 *
 * `diagnostic_registry` is useful for inspecting and testing the exact roots
 * that the current code would bind.  It is not an authority registry:
 * `BuildCanonicalProductionRegistryV1` returns it to callers only when every
 * residual is zero.
 */
struct AssessmentV1 {
    uint16_t version{kCanonicalRegistryBuilderVersionV1};
    ut::ProductionProgramRegistryV1 diagnostic_registry{};
    cb::ProgramTable universal_parent_program{};
    cb::ProgramTable normalized_root_program{};
    cb::ProgramTableCommitmentPair universal_parent_program_root{};
    cb::ProgramTableCommitmentPair normalized_root_program_root{};
    ut::ProductionFamilyProgramMigrationStatusV1 family_migration{};
    np::ManifestV1 normalized_program_manifest{};
    std::vector<FamilySemanticResidualV1> family_residuals;
    uint32_t residual_mask{0};
    bool canonical_family_sources{false};
    bool every_family_semantically_complete{false};
    bool exact_semantic_endpoint_union{false};
    bool exact_parent_program_slots{false};
    bool parent_program_roots_reconstructed{false};
    bool registry_roots_reconstructed{false};
    bool structurally_valid_diagnostic_registry{false};
    bool authority_eligible{false};
    std::string note;
};

/**
 * Rebuild the two parent ProgramTables and all 28 production family sources
 * from their canonical constructors, then compute the diagnostic registry.
 * No caller-supplied ProgramTable or semantic-completeness bit is accepted.
 */
[[nodiscard]] AssessmentV1 AssessCanonicalProductionRegistryV1(
    const sites::ProductionProofSiteManifest& manifest,
    const sched::ProductionAggregationSchedule& schedule);

/**
 * Strict production builder.  On any residual this returns false and clears
 * `out`; the diagnostic assessment still reports the exact reason.  In
 * particular, the current 14 partial family sources cannot be promoted by a
 * structural registry validator.
 */
[[nodiscard]] bool BuildCanonicalProductionRegistryV1(
    const sites::ProductionProofSiteManifest& manifest,
    const sched::ProductionAggregationSchedule& schedule,
    ut::ProductionProgramRegistryV1& out,
    AssessmentV1* assessment = nullptr,
    std::string* why = nullptr);

/**
 * Validate that a diagnostic registry is byte-for-byte the result of the
 * canonical builders.  This rejects a substituted parent ProgramTable or
 * family program even when the generic structural registry validator accepts
 * the attacker's recomputed roots.
 *
 * This function does not make the registry authority eligible.
 */
[[nodiscard]] bool ValidateCanonicalDiagnosticRegistryV1(
    const sites::ProductionProofSiteManifest& manifest,
    const sched::ProductionAggregationSchedule& schedule,
    const ut::ProductionProgramRegistryV1& candidate,
    std::string* why = nullptr);

} // namespace matmul::v4::rc::production_canonical_registry

#endif // BTX_MATMUL_MATMUL_V4_RC_STAGE3_PRODUCTION_CANONICAL_REGISTRY_H
