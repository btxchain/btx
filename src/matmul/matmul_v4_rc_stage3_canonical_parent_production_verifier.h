// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/MIT.

#ifndef BTX_MATMUL_MATMUL_V4_RC_STAGE3_CANONICAL_PARENT_PRODUCTION_VERIFIER_H
#define BTX_MATMUL_MATMUL_V4_RC_STAGE3_CANONICAL_PARENT_PRODUCTION_VERIFIER_H

#include <matmul/matmul_v4_rc_stage3_canonical_parent_consensus.h>
#include <matmul/matmul_v4_rc_stage3_production_canonical_registry.h>
#include <matmul/matmul_v4_rc_stage3_semantic_endpoint_program_bridge.h>

#include <cstdint>
#include <string>
#include <vector>

class CBlock;

namespace Consensus {
struct Params;
}

namespace matmul::v4::rc::canonical_parent_production_verifier {

namespace cpc = canonical_parent_consensus;
namespace ncb = normalized_consensus_binding;
namespace nav3 = normalized_authority;
namespace pcr = production_canonical_registry;
namespace bridge = semantic_endpoint_program_bridge;
namespace sites = soundness_scenarios;
namespace sched = aggregation_scheduler;

inline constexpr uint16_t kVersionV1 = 1;

enum FrozenSpecResidualV1 : uint32_t {
    kResidualBlockDimensions = 1U << 0,
    kResidualSiteManifest = 1U << 1,
    kResidualAggregationSchedule = 1U << 2,
    kResidualCanonicalRegistry = 1U << 3,
    kResidualEndpointProgramMap = 1U << 4,
    kResidualEndpointOccurrences = 1U << 5,
    kResidualRoleHalfPrograms = 1U << 6,
    kResidualRoleHalfShapes = 1U << 7,
    kResidualPublicOutputAbi = 1U << 8,
    kResidualConsensusRegistryPin = 1U << 9,
};

/**
 * Fail-closed audit of everything required to construct the binary parent
 * without reading receipt configuration.
 *
 * The diagnostic role schedule contains only entries whose program key,
 * production occurrence count and endpoint manifest are derivable from the
 * immutable production inventory.  `spec_derivable` requires all 52 entries
 * and the two executable role-half ProgramTables/shapes.
 */
struct FrozenSpecAssessmentV1 {
    uint16_t version{kVersionV1};
    sites::ProductionProofSiteManifest site_manifest;
    sched::ProductionAggregationSchedule aggregation_schedule;
    pcr::AssessmentV1 registry;
    bridge::SemanticEndpointProgramBridgeManifestV1
        endpoint_program_map;
    std::vector<cpc::FrozenRoleScheduleV1>
        diagnostic_role_schedule;
    /**
     * Canonically rebuilt role-half adapter.  This is diagnostic while any
     * other residual remains: it is not a caller-selectable registry and is
     * copied into the consensus spec only by BuildFrozenBinaryParentSpecV1
     * after every independent production residual is closed.
     */
    cpc::FrozenBinaryParentSpecV1 diagnostic_frozen_spec;
    uint256 block_dimension_commitment{};
    uint32_t derived_endpoint_occurrences{0};
    uint32_t derived_role_programs{0};
    uint32_t residual_mask{0};
    bool block_dimensions_canonical{false};
    bool manifest_canonical{false};
    bool aggregation_schedule_canonical{false};
    bool registry_rebuilt_from_canonical_sources{false};
    bool consensus_registry_pin_matches{false};
    bool exact_endpoint_order{false};
    bool exact_endpoint_occurrence_schedule{false};
    bool exact_role_program_schedule{false};
    bool role_half_programs_available{false};
    bool role_half_shapes_available{false};
    bool public_output_abi_available{false};
    bool spec_derivable{false};
    bool authority{false};
    std::string role_half_adapter_note;
    std::vector<std::string> missing_inputs;
    std::string note;
};

[[nodiscard]] FrozenSpecAssessmentV1
AssessFrozenBinaryParentSpecV1(
    const CBlock& block,
    const Consensus::Params& params,
    int32_t height);

/**
 * Strict builder.  It never accepts a receipt, ProgramTable, shape, count or
 * endpoint order argument.  Until the canonical registry exposes executable
 * role-half programs/shapes this returns false and clears `out`.
 */
[[nodiscard]] bool BuildFrozenBinaryParentSpecV1(
    const CBlock& block,
    const Consensus::Params& params,
    int32_t height,
    cpc::FrozenBinaryParentSpecV1& out,
    FrozenSpecAssessmentV1* assessment = nullptr,
    std::string* why = nullptr);

/**
 * Test/audit validator for the diagnostic adapter already rebuilt by
 * AssessFrozenBinaryParentSpecV1.  It checks exact equality to the canonical
 * role schedule, ProgramTables, manifest-derived shapes and ABI bases and
 * rechecks every ProgramTable commitment.  It is deliberately not an
 * authority API: BuildFrozenBinaryParentSpecV1 always performs its own
 * receipt-independent assessment.
 */
[[nodiscard]] bool ValidateDiagnosticRoleHalfAdapterV1(
    const FrozenSpecAssessmentV1& assessment,
    const cpc::FrozenBinaryParentSpecV1& candidate,
    std::string* why = nullptr);

enum class MechanismVerifyStatusV1 : uint8_t {
    AttachmentDecodeFailed = 0,
    FrozenSpecUnavailable = 1,
    NativeParentRejected = 2,
    MechanismVerifiedNotAuthority = 3,
    /**
     * The native parent proof verified after a receipt-independent rebuild,
     * and that rebuilt parent constrains complete child acceptance in the
     * same proof.  Current production construction cannot return this value:
     * its authority flags remain false until the complete V13 child
     * fixed-point and semantic inventory are both executable.
     */
    AuthorityVerified = 4,
};

/**
 * Full block-bound mechanism entry.
 *
 * BNV3/NAV3 is decoded from `block`, the public statement is rebuilt from the
 * header and consensus parameters, and the frozen parent spec is rebuilt
 * independently.  The decoded roles are passed only as claimed child public
 * outputs; they cannot select order, counts, manifests, programs, shapes or
 * output columns.
 *
 * Success remains non-authoritative while the canonical child verifier reports
 * `full_child_acceptance_constrained == false`. `AuthorityVerified` is returned
 * only when both that independently rebuilt property and the canonical
 * parent's authority predicate are true; a mismatch is rejected.
 */
[[nodiscard]] MechanismVerifyStatusV1
VerifyAttachedCanonicalParentMechanismV1(
    const CBlock& block,
    const Consensus::Params& params,
    int32_t height,
    const uint256& target,
    FrozenSpecAssessmentV1* assessment = nullptr,
    cpc::RebuiltCanonicalParentV1* rebuilt = nullptr,
    std::string* why = nullptr);

inline constexpr bool kExecutableMechanismV1 = true;
inline constexpr bool kAuthorityReadyV1 = false;
static_assert(!kAuthorityReadyV1);

} // namespace matmul::v4::rc::canonical_parent_production_verifier

#endif
