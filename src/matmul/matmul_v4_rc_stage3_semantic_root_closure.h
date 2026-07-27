// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BTX_MATMUL_MATMUL_V4_RC_STAGE3_SEMANTIC_ROOT_CLOSURE_H
#define BTX_MATMUL_MATMUL_V4_RC_STAGE3_SEMANTIC_ROOT_CLOSURE_H

#include <matmul/matmul_v4_rc_air_quotient_alg.h>
#include <matmul/matmul_v4_rc_stage3_production_family_programs.h>
#include <matmul/matmul_v4_rc_stage3_semantic_status.h>

#include <array>
#include <cstdint>
#include <string>
#include <vector>

namespace matmul::v4::rc::semantic_root_closure {

namespace ah = alg_hash;
namespace aq = air_quotient;
namespace gf = gkr_field;
namespace sites = soundness_scenarios;
namespace topo = universal_topology;

inline constexpr uint16_t kSemanticRootClosureVersionV1 = 1;
inline constexpr uint32_t kSemanticRootU32WordsV1 = 8;
inline constexpr uint32_t kSemanticRootFp3U32WordsV1 = 6;
inline constexpr uint32_t kSemanticRootNoFamilyV1 = UINT32_MAX;
inline constexpr uint32_t kSemanticRootNoColumnV1 = UINT32_MAX;

/**
 * Missing-source bits are evidence, not readiness switches.  The canonical
 * builder derives every bit from the program registry, relation-cell audit,
 * provenance graph and semantic audit.  A downstream gate may close only
 * when the resulting mask is zero for every endpoint.
 */
enum SemanticRootMissingSourceV1 : uint32_t {
    MissingExactProgramTableV1 = 1U << 0,
    MissingRelationProofCellV1 = 1U << 1,
    MissingSameTraceCtlValueAliasV1 = 1U << 2,
    MissingRecursiveProvenanceEqualityV1 = 1U << 3,
    MissingChildReceiptAcceptanceCellV1 = 1U << 4,
    MissingTransitiveSemanticClosureV1 = 1U << 5,
    MissingRecursiveCtlRationalIdentityV1 = 1U << 6,
};

/**
 * Symbolic cells in the selected exact-row degree-two CTL child.  `last_row`
 * is symbolic because each role has a different exact schedule; the
 * normalized parent must substitute a literal row and direct-alias these
 * three cells from the executed child proof.
 */
struct SemanticCtlTerminalDescriptorV1 {
    uint16_t ctl_layout_version{0};
    uint32_t namespace_column{kSemanticRootNoColumnV1};
    uint32_t stage_column{kSemanticRootNoColumnV1};
    uint32_t address_column{kSemanticRootNoColumnV1};
    uint32_t value_column{kSemanticRootNoColumnV1};
    uint32_t multiplicity_column{kSemanticRootNoColumnV1};
    uint32_t inverse_alpha1_column{kSemanticRootNoColumnV1};
    uint32_t inverse_alpha2_column{kSemanticRootNoColumnV1};
    uint32_t running_alpha1_column{kSemanticRootNoColumnV1};
    uint32_t running_alpha2_column{kSemanticRootNoColumnV1};
    bool last_row{false};
    bool relation_value_same_trace{false};
    bool tuple_columns_owned{false};
    bool ordered_schedule_and_multiplicity_pinned{false};
    bool post_commit_challenges_bound{false};
    bool denominators_nonzero_constrained{false};
    bool global_terminal_zero_consumed{false};
    bool recursive_rational_identity_consumed{false};

    bool operator==(const SemanticCtlTerminalDescriptorV1&) const = default;
};

/**
 * One exact endpoint row in the semantic-root inventory.
 *
 * The family/program fields are populated only when the canonical production
 * registry itself claims this endpoint semantically complete.  A nearby
 * partial helper table is never silently promoted into an endpoint key.
 * AlgHash limbs are split into lo32/hi32 words before they enter the
 * manifest commitment, preventing the Goldilocks x/(x+p) alias.
 */
struct SemanticRootEndpointManifestV1 {
    RCStage3RelationEndpoint endpoint{};
    RCStage3RelationRole role{};
    uint32_t role_ordinal{0};
    uint32_t endpoint_ordinal{0};

    uint32_t family_index{kSemanticRootNoFamilyV1};
    sites::ProductionProofSiteKind proof_site_kind{};
    std::array<uint32_t, kSemanticRootU32WordsV1>
        program_external_sha256d_words{};
    std::array<uint32_t, kSemanticRootU32WordsV1>
        program_recursive_alg_hash_words{};
    bool exact_program_table{false};

    uint32_t relation_column{kSemanticRootNoColumnV1};
    bool relation_proof_cell{false};
    SemanticCtlTerminalDescriptorV1 ctl;

    uint32_t provenance_node_index{0};
    uint32_t provenance_producer_count{0};
    bool recursive_provenance_equality{false};
    bool child_receipt_acceptance_cell{false};

    bool local_relation_complete{false};
    bool producer_provenance_complete{false};
    bool semantic_complete{false};
    bool recursively_consumed{false};
    uint32_t missing_sources{0};

    std::string relation_source;
    std::string exact_missing_source;

    bool operator==(const SemanticRootEndpointManifestV1&) const = default;
};

struct SemanticRootRoleManifestV1 {
    RCStage3RelationRole role{};
    uint32_t first_endpoint_index{0};
    uint32_t endpoint_count{0};
    uint32_t exact_program_endpoints{0};
    uint32_t ctl_value_alias_endpoints{0};
    uint32_t semantic_complete_endpoints{0};
    uint32_t recursively_consumed_endpoints{0};
    bool complete{false};

    bool operator==(const SemanticRootRoleManifestV1&) const = default;
};

struct SemanticRootClosureManifestV1 {
    uint16_t version{kSemanticRootClosureVersionV1};
    uint256 production_site_manifest_commitment{};
    uint256 closure_commitment{};
    std::vector<SemanticRootRoleManifestV1> roles;
    std::vector<SemanticRootEndpointManifestV1> endpoints;

    uint32_t exact_program_endpoints{0};
    uint32_t relation_proof_cell_endpoints{0};
    uint32_t same_trace_ctl_value_endpoints{0};
    uint32_t recursive_provenance_endpoints{0};
    uint32_t child_receipt_acceptance_endpoints{0};
    uint32_t semantic_complete_endpoints{0};
    uint32_t recursively_consumed_endpoints{0};
    uint32_t complete_roles{0};

    bool exact_role_order{false};
    bool exact_endpoint_order{false};
    bool production_registry_canonical{false};
    bool no_structural_stub_claims{false};
    bool canonical_u32_commitment{false};
    bool local_inventory_complete{false};
    bool recursive_semantic_closure_complete{false};
    bool production_authority{false};
    std::vector<std::string> residuals;

    bool operator==(const SemanticRootClosureManifestV1&) const = default;
};

/**
 * Build the exact inventory from the live production registries/audits.
 * Neither the 52 endpoint capability counts nor the 14 role completion bits
 * are literals.  `production_mode` is forwarded to the strict semantic audit.
 */
[[nodiscard]] SemanticRootClosureManifestV1
BuildSemanticRootClosureManifestV1(
    const RCStage3CoupledShape& shape,
    const gf::Fp3& gamma,
    const gf::Fp3& alpha,
    uint8_t extract_scale_e = 0,
    bool production_mode = false);

[[nodiscard]] uint256 ComputeSemanticRootClosureCommitmentV1(
    const SemanticRootClosureManifestV1& manifest);

/** Fail-closed equality to a freshly regenerated canonical inventory. */
[[nodiscard]] bool ValidateSemanticRootClosureManifestV1(
    const SemanticRootClosureManifestV1& manifest,
    const RCStage3CoupledShape& shape,
    const gf::Fp3& gamma,
    const gf::Fp3& alpha,
    uint8_t extract_scale_e = 0,
    bool production_mode = false,
    std::string* why = nullptr);

/**
 * Exact per-endpoint receipt payload expected from the future same-parent
 * normalized verifier.  All roots and every Fp3 terminal coordinate are
 * represented by u32 words.  Thus this ABI has no raw u64 field absorb.
 */
struct SemanticEndpointReceiptStatementV1 {
    RCStage3RelationEndpoint endpoint{};
    RCStage3RelationRole role{};
    uint32_t family_index{kSemanticRootNoFamilyV1};
    std::array<uint32_t, kSemanticRootU32WordsV1>
        program_recursive_alg_hash_words{};
    std::array<uint32_t, kSemanticRootU32WordsV1>
        relation_semantic_root_words{};
    std::array<uint32_t, kSemanticRootU32WordsV1>
        provenance_root_words{};
    std::array<uint32_t, kSemanticRootU32WordsV1>
        receipt_semantic_root_words{};
    std::array<uint32_t, kSemanticRootU32WordsV1>
        ctl_schedule_commitment_words{};
    std::array<uint32_t, kSemanticRootU32WordsV1>
        ctl_challenge_commitment_words{};
    std::array<uint32_t, 2 * kSemanticRootFp3U32WordsV1>
        ctl_terminal_words{};
    uint32_t ctl_rational_identity_acceptance{0};
    uint32_t child_acceptance{0};

    bool operator==(const SemanticEndpointReceiptStatementV1&) const = default;
};

struct SemanticRootReceiptStatementV1 {
    uint16_t version{kSemanticRootClosureVersionV1};
    uint256 closure_manifest_commitment{};
    std::vector<SemanticEndpointReceiptStatementV1> endpoints;
    uint256 statement_commitment{};
    /** Status only. It is recomputed from the manifest, never accepted from
     * serialized receipt data. */
    bool all_sources_available{false};
    bool recursively_consumable{false};
    bool production_authority{false};

    bool operator==(const SemanticRootReceiptStatementV1&) const = default;
};

[[nodiscard]] uint256 ComputeSemanticRootReceiptStatementCommitmentV1(
    const SemanticRootReceiptStatementV1& statement);

/**
 * Validate the exact receipt ABI and root equalities.  This does not grant
 * source ownership: it returns a valid binding statement even while
 * `all_sources_available` remains false, allowing a normalized parent to
 * direct-alias the exact missing cells as they are implemented.
 */
[[nodiscard]] bool ValidateSemanticRootReceiptStatementV1(
    const SemanticRootClosureManifestV1& manifest,
    const SemanticRootReceiptStatementV1& statement,
    std::string* why = nullptr);

/**
 * Canonical inventory AIR.  It proves the exact current program/cell/status
 * manifest survives quotient/FRI compilation.  It deliberately does not
 * prove endpoint values or child verification; those remain ordinary
 * same-parent source cells described by SemanticRootReceiptStatementV1.
 */
struct SemanticRootClosureAirLayoutV1 {
    uint32_t claimed_endpoint{0};
    uint32_t claimed_role{0};
    uint32_t claimed_role_ordinal{0};
    uint32_t claimed_endpoint_ordinal{0};
    uint32_t claimed_family_index{0};
    uint32_t claimed_proof_site_kind{0};
    uint32_t claimed_relation_column{0};
    uint32_t claimed_missing_sources{0};
    uint32_t claimed_program_external_base{0};
    uint32_t claimed_program_recursive_base{0};

    uint32_t expected_active{0};
    uint32_t expected_endpoint{0};
    uint32_t expected_role{0};
    uint32_t expected_role_ordinal{0};
    uint32_t expected_endpoint_ordinal{0};
    uint32_t expected_family_index{0};
    uint32_t expected_proof_site_kind{0};
    uint32_t expected_relation_column{0};
    uint32_t expected_missing_sources{0};
    uint32_t expected_program_external_base{0};
    uint32_t expected_program_recursive_base{0};
    uint32_t total_columns{0};
};

struct SemanticRootClosureAirV1 {
    uint16_t version{kSemanticRootClosureVersionV1};
    uint256 closure_manifest_commitment{};
    SemanticRootClosureAirLayoutV1 layout;
    aq::AirConstraintSystem<gf::Fp3> cs;
    std::vector<std::vector<gf::Fp3>> columns;
    uint32_t active_rows{0};
    uint32_t violations{0};
    bool exact_manifest_pinned{false};
    bool values_are_ordinary_witness{false};
    bool only_expected_schedule_preprocessed{false};
    bool recursive_semantic_closure_complete{false};
    bool production_authority{false};
    bool valid{false};
    std::string note;
};

[[nodiscard]] SemanticRootClosureAirV1
BuildSemanticRootClosureAirV1(
    const SemanticRootClosureManifestV1& manifest);

[[nodiscard]] uint32_t CountSemanticRootClosureAirViolationsV1(
    const aq::AirConstraintSystem<gf::Fp3>& cs,
    const std::vector<std::vector<gf::Fp3>>& columns);

/**
 * Consensus decoders must reject a noncanonical raw Fp3 cell before reducing
 * it to a u32 statement word.  In particular, raw c0==p is rejected rather
 * than accepted as another encoding of zero.
 */
[[nodiscard]] bool DecodeCanonicalSemanticU32CellV1(
    const gf::Fp3& cell,
    uint32_t& out);

inline constexpr bool kSemanticRootClosureRecursiveAuthorityV1 = false;
inline constexpr bool kSemanticRootClosureProductionCompleteV1 = false;
static_assert(!kSemanticRootClosureRecursiveAuthorityV1);
static_assert(!kSemanticRootClosureProductionCompleteV1);

} // namespace matmul::v4::rc::semantic_root_closure

#endif // BTX_MATMUL_MATMUL_V4_RC_STAGE3_SEMANTIC_ROOT_CLOSURE_H
