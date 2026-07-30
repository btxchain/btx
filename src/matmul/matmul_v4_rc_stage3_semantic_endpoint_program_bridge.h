// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BTX_MATMUL_MATMUL_V4_RC_STAGE3_SEMANTIC_ENDPOINT_PROGRAM_BRIDGE_H
#define BTX_MATMUL_MATMUL_V4_RC_STAGE3_SEMANTIC_ENDPOINT_PROGRAM_BRIDGE_H

#include <matmul/matmul_v4_rc_air_quotient_alg.h>
#include <matmul/matmul_v4_rc_stage3_production_family_programs.h>
#include <matmul/matmul_v4_rc_stage3_relation_closure.h>

#include <array>
#include <cstdint>
#include <string>
#include <vector>

namespace matmul::v4::rc::semantic_endpoint_program_bridge {

namespace sites = soundness_scenarios;

inline constexpr uint16_t kSemanticEndpointProgramBridgeVersionV1 = 1;
inline constexpr uint32_t kSemanticEndpointProgramBridgeDigestWordsV1 = 8;
inline constexpr uint32_t kSemanticEndpointProgramBridgeNoFamilyV1 =
    UINT32_MAX;
inline constexpr uint32_t kSemanticEndpointProgramBridgeNoColumnV1 =
    UINT32_MAX;

/**
 * Exact reason why an endpoint cannot yet be direct-aliased from a selected
 * production ProgramTable into the already-executed relation/CTL product.
 *
 * These are evidence bits, not readiness switches.  In particular,
 * MissingRecursiveChildAcceptanceV1 remains set for every endpoint in V1.
 */
enum SemanticEndpointProgramMissingV1 : uint32_t {
    MissingSelectedProgramKeyV1 = 1U << 0,
    MissingCanonicalOutputMetadataV1 = 1U << 1,
    MissingExecutedRelationCellV1 = 1U << 2,
    MissingSameTraceCtlAliasV1 = 1U << 3,
    MissingRecursiveChildAcceptanceV1 = 1U << 4,
};

/**
 * One endpoint-to-family binding.
 *
 * A family may appear in several records: this is the explicit one-to-many
 * expansion that was absent from ProductionFamilyProgramSourceV1's
 * single-endpoint semantic claim.  `canonical_output_metadata` is granted
 * only after byte-for-byte equality with the named canonical ProgramTable
 * builder and exact role equality.  It is never inferred from a family name,
 * public-input schema, width, constraint count, or one-column stub.
 */
struct SemanticEndpointProgramBindingV1 {
    RCStage3RelationEndpoint endpoint{};
    RCStage3RelationRole role{};
    uint32_t endpoint_ordinal{0};

    uint32_t family_index{kSemanticEndpointProgramBridgeNoFamilyV1};
    sites::ProductionProofSiteKind proof_site_kind{};
    std::array<uint32_t, kSemanticEndpointProgramBridgeDigestWordsV1>
        program_external_sha256d_words{};
    std::array<uint32_t, kSemanticEndpointProgramBridgeDigestWordsV1>
        program_recursive_alg_hash_words{};

    uint32_t relation_column{kSemanticEndpointProgramBridgeNoColumnV1};
    bool selected_program_key{false};
    bool exact_program_table_match{false};
    bool registry_semantic_claim{false};
    bool canonical_output_metadata{false};
    bool executed_relation_cell{false};
    bool relation_column_exact{false};
    bool same_trace_ctl_alias{false};
    bool direct_alias_ready{false};
    bool recursive_child_accepted{false};
    uint32_t missing_sources{0};
    std::string source;
    std::string residual;

    bool operator==(
        const SemanticEndpointProgramBindingV1&) const = default;
};

struct SemanticProgramFamilyCoverageV1 {
    uint32_t family_index{0};
    sites::ProductionProofSiteKind proof_site_kind{};
    RCStage3RelationRole role{};
    uint32_t registry_claimed_endpoints{0};
    uint32_t exact_output_endpoints{0};
    uint32_t direct_alias_endpoints{0};
    bool exact_selected_program{false};

    bool operator==(
        const SemanticProgramFamilyCoverageV1&) const = default;
};

struct SemanticEndpointProgramBridgeManifestV1 {
    uint16_t version{kSemanticEndpointProgramBridgeVersionV1};
    uint256 production_site_manifest_commitment{};
    uint256 bridge_commitment{};
    std::vector<SemanticEndpointProgramBindingV1> endpoints;
    std::vector<SemanticProgramFamilyCoverageV1> families;

    uint32_t selected_program_key_endpoints{0};
    uint32_t registry_semantic_claim_endpoints{0};
    uint32_t canonical_output_metadata_endpoints{0};
    uint32_t executed_relation_cell_endpoints{0};
    uint32_t exact_relation_column_endpoints{0};
    uint32_t direct_alias_endpoints{0};
    uint32_t recursive_child_accepted_endpoints{0};
    uint32_t complete_roles{0};

    bool exact_endpoint_order{false};
    bool exact_family_order{false};
    bool production_sources_canonical{false};
    bool no_duplicate_endpoint_bindings{false};
    bool no_cross_role_bindings{false};
    bool canonical_u32_commitment{false};
    bool recursive_semantic_closure_complete{false};
    bool production_authority{false};

    bool operator==(
        const SemanticEndpointProgramBridgeManifestV1&) const = default;
};

/**
 * Build the canonical bridge from the selected 28-family production source
 * inventory and the executable relation-cell audit.
 */
[[nodiscard]] SemanticEndpointProgramBridgeManifestV1
BuildSemanticEndpointProgramBridgeManifestV1();

[[nodiscard]] uint256 ComputeSemanticEndpointProgramBridgeCommitmentV1(
    const SemanticEndpointProgramBridgeManifestV1& manifest);

/**
 * Fail-closed canonical regeneration.  This rejects endpoint omission,
 * reordering, duplication, cross-role substitution, output-column
 * substitution, program-key substitution, and commitment tampering.
 */
[[nodiscard]] bool ValidateSemanticEndpointProgramBridgeManifestV1(
    const SemanticEndpointProgramBridgeManifestV1& manifest,
    std::string* why = nullptr);

/**
 * Decode one commitment word from an Fp3 receipt cell.  The cell must be an
 * unreduced canonical Goldilocks representative whose extension coordinates
 * are zero and whose value fits in u32.  Thus raw x+p representatives are
 * rejected before field arithmetic can erase the distinction.
 */
[[nodiscard]] bool DecodeSemanticEndpointProgramCanonicalU32V1(
    const gkr_field::Fp3& cell,
    uint32_t& out,
    std::string* why = nullptr);

/**
 * Compact proof product for the exact endpoint/program map.  The endpoint
 * values and program keys are ordinary witness columns.  The canonical
 * expected schedule is verifier-recomputed preprocessing and is pinned at the
 * row-wise backend's OOD point.  This proves the mapping commitment survived
 * quotient/FRI; it does not execute any mapped child proof.
 */
struct SemanticEndpointProgramBridgeAirLayoutV1 {
    uint32_t claimed_endpoint{0};
    uint32_t claimed_role{0};
    uint32_t claimed_ordinal{0};
    uint32_t claimed_family{0};
    uint32_t claimed_site_kind{0};
    uint32_t claimed_relation_column{0};
    uint32_t claimed_status_bits{0};
    uint32_t claimed_missing_sources{0};
    uint32_t claimed_external_base{0};
    uint32_t claimed_recursive_base{0};

    uint32_t expected_active{0};
    uint32_t expected_endpoint{0};
    uint32_t expected_role{0};
    uint32_t expected_ordinal{0};
    uint32_t expected_family{0};
    uint32_t expected_site_kind{0};
    uint32_t expected_relation_column{0};
    uint32_t expected_status_bits{0};
    uint32_t expected_missing_sources{0};
    uint32_t expected_external_base{0};
    uint32_t expected_recursive_base{0};
    uint32_t total_columns{0};
};

struct SemanticEndpointProgramBridgeAirV1 {
    uint16_t version{kSemanticEndpointProgramBridgeVersionV1};
    uint256 bridge_commitment{};
    uint256 proof_seed{};
    SemanticEndpointProgramBridgeAirLayoutV1 layout;
    air_quotient::AirConstraintSystem<gkr_field::Fp3> cs;
    std::vector<std::vector<gkr_field::Fp3>> columns;
    uint32_t active_rows{0};
    uint32_t violations{0};
    bool mapping_commitment_bound{false};
    bool only_expected_schedule_preprocessed{false};
    bool recursive_child_consumption{false};
    bool production_authority{false};
    bool valid{false};
    std::string note;
};

[[nodiscard]] uint256
ComputeSemanticEndpointProgramBridgeAirSeedV1(
    const SemanticEndpointProgramBridgeManifestV1& manifest);

[[nodiscard]] SemanticEndpointProgramBridgeAirV1
BuildSemanticEndpointProgramBridgeAirV1(
    const SemanticEndpointProgramBridgeManifestV1& manifest);

[[nodiscard]] uint32_t
CountSemanticEndpointProgramBridgeAirViolationsV1(
    const air_quotient::AirConstraintSystem<gkr_field::Fp3>& cs,
    const std::vector<std::vector<gkr_field::Fp3>>& columns);

inline constexpr bool
    kSemanticEndpointProgramBridgeRecursiveConsumptionReadyV1 = false;
inline constexpr bool
    kSemanticEndpointProgramBridgeAuthorityV1 = false;
static_assert(
    !kSemanticEndpointProgramBridgeRecursiveConsumptionReadyV1);
static_assert(!kSemanticEndpointProgramBridgeAuthorityV1);

} // namespace matmul::v4::rc::semantic_endpoint_program_bridge

#endif // BTX_MATMUL_MATMUL_V4_RC_STAGE3_SEMANTIC_ENDPOINT_PROGRAM_BRIDGE_H
