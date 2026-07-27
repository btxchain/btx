// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BTX_MATMUL_MATMUL_V4_RC_STAGE3_UNIVERSAL_TOPOLOGY_H
#define BTX_MATMUL_MATMUL_V4_RC_STAGE3_UNIVERSAL_TOPOLOGY_H

#include <matmul/matmul_v4_rc_stage3_aggregation_schedule.h>
#include <matmul/matmul_v4_rc_stage3_constraint_bytecode.h>

#include <cstdint>
#include <string>
#include <vector>

namespace matmul::v4::rc::universal_topology {

namespace ah = alg_hash;
namespace cb = constraint_bytecode;
namespace sched = aggregation_scheduler;
namespace sites = soundness_scenarios;

inline constexpr uint16_t kProductionProgramRegistryVersionV1 = 1;
inline constexpr uint16_t kUniversalStatementVersionV1 = 1;
inline constexpr uint32_t kProductionProgramFamilyCountV1 = 28;
inline constexpr uint32_t kUniversalVerifierColumnCapV1 = 16'384;
inline constexpr uint32_t kDeprecatedMonolithicVerifierColumnsV1 = 124'802;
inline constexpr uint32_t kDeprecatedWidthLeafShardsV1 = 244;
inline constexpr uint32_t kDeprecatedWidthParentsV1 = 82;

struct ByteCommitmentPairV1 {
    uint64_t byte_length{0};
    uint256 external_sha256d{};
    ah::Digest recursive_alg_hash{};
    bool same_canonical_bytes{false};

    bool operator==(const ByteCommitmentPairV1&) const = default;
};

/** Both digests commit the same length-delimited bytes. */
[[nodiscard]] ByteCommitmentPairV1 CommitCanonicalBytesV1(
    const char* domain,
    const std::vector<unsigned char>& bytes);

/**
 * Build-time source for one immutable production family. The ProgramTable is
 * the actual verifying key: no callback or host-selected table is accepted.
 * `public_input_schema` is a canonical byte ABI (not a public-input value).
 */
struct ProductionFamilyProgramSourceV1 {
    uint32_t family_index{0};
    sites::ProductionProofSiteKind kind{};
    RCStage3RelationRole role{};
    cb::ProgramTable program;
    std::vector<unsigned char> public_input_schema;
    std::vector<uint16_t> semantic_endpoints;
    bool semantic_relation_complete{false};
};

struct ProductionFamilyProgramEntryV1 {
    uint32_t family_index{0};
    sites::ProductionProofSiteKind kind{};
    RCStage3RelationRole role{};
    uint32_t maximum_columns{0};
    uint32_t constraint_count{0};
    uint32_t maximum_constraint_degree{0};
    cb::ProgramTableCommitmentPair program;
    ByteCommitmentPairV1 public_input_schema;
    std::vector<uint16_t> semantic_endpoints;
    bool semantic_relation_complete{false};

    bool operator==(const ProductionFamilyProgramEntryV1&) const = default;
};

struct ProductionProgramRegistryV1 {
    uint16_t version{kProductionProgramRegistryVersionV1};
    uint256 site_manifest_commitment{};
    uint256 aggregation_schedule_commitment{};
    std::vector<ProductionFamilyProgramEntryV1> families;
    cb::ProgramTableCommitmentPair universal_parent_verifier;
    cb::ProgramTableCommitmentPair normalized_root_verifier;
    uint32_t universal_parent_columns{0};
    uint32_t normalized_root_columns{0};
    uint256 external_registry_commitment{};
    ah::Digest recursive_registry_commitment{};

    bool exact_family_order{false};
    bool every_program_canonical{false};
    bool every_public_input_schema_bound{false};
    bool every_program_within_column_cap{false};
    bool every_semantic_relation_complete{false};

    bool operator==(const ProductionProgramRegistryV1&) const = default;
};

/**
 * Compact public/consensus pin. The four-limb recursive AlgHash digest is the
 * sole ProgramTable/verifying-key authority and is serialized directly in
 * consensus parameters/public inputs. SHA256d is audit/transport metadata,
 * not an alternative acceptance commitment and not a cross-hash hybrid.
 */
struct ProductionProgramRegistryPublicPinV1 {
    uint16_t version{kProductionProgramRegistryVersionV1};
    uint256 site_manifest_commitment{};
    uint256 aggregation_schedule_commitment{};
    uint256 external_registry_commitment{};
    ah::Digest recursive_registry_commitment{};
    uint256 binding{};
    bool recursive_alg_hash_is_program_authority{true};
    bool external_sha256d_is_audit_only{true};

    bool operator==(
        const ProductionProgramRegistryPublicPinV1&) const = default;
};

[[nodiscard]] ProductionProgramRegistryPublicPinV1
BuildProductionProgramRegistryPublicPinV1(
    const ProductionProgramRegistryV1& registry);

/** Convert the complete registry pin into the exact Stage-3 proof ABI. */
[[nodiscard]] ProductionProgramConsensusPinV1
BuildProductionProgramConsensusPinV1(
    const ProductionProgramRegistryV1& registry);

[[nodiscard]] bool ValidateProductionProgramRegistryPublicPinV1(
    const ProductionProgramRegistryV1& registry,
    const ProductionProgramRegistryPublicPinV1& pin,
    const uint256& audit_expected_external_commitment,
    const ah::Digest& consensus_expected_recursive_commitment,
    std::string* why = nullptr);

/**
 * Build the single program registry consumed by consensus serialization and
 * by the recursive verifier. SHA256d is the external/audit commitment.
 * AlgHash is the in-recursion commitment. Both are computed from the same
 * ordered registry fields, and every individual ProgramTable pair is derived
 * from one canonical serialization.
 */
[[nodiscard]] ProductionProgramRegistryV1
BuildProductionProgramRegistryV1(
    const sites::ProductionProofSiteManifest& manifest,
    const sched::ProductionAggregationSchedule& schedule,
    const std::vector<ProductionFamilyProgramSourceV1>& families,
    const cb::ProgramTable& universal_parent_verifier,
    const cb::ProgramTable& normalized_root_verifier);

[[nodiscard]] bool ValidateProductionProgramRegistryV1(
    const sites::ProductionProofSiteManifest& manifest,
    const sched::ProductionAggregationSchedule& schedule,
    const ProductionProgramRegistryV1& registry,
    const uint256& expected_external_commitment,
    const ah::Digest& expected_recursive_commitment,
    std::string* why = nullptr);

struct UniversalTopologyAssessmentV1 {
    uint64_t relation_leaf_sites{0};
    uint64_t arity_four_parent_sites{0};
    uint64_t final_tree_parent_sites{0};
    uint64_t exact_total_sites{0};
    uint32_t deprecated_width_leaf_shards{
        kDeprecatedWidthLeafShardsV1};
    uint32_t deprecated_width_parents{
        kDeprecatedWidthParentsV1};
    uint64_t rejected_product_site_diagnostic{0};
    /** Current one-proof-per-shard topology. */
    uint64_t shard_proof_instances{0};
    /** Coverage inventory, not automatically independent union terms. A
     * family proof's theorem must absorb these rows/constraints internally. */
    uint64_t shard_coverage_and_recursion_events{0};
    /** Candidate only: one quotient/FRI proof per registered family. */
    uint64_t family_batched_leaf_proof_instances{0};
    uint64_t family_batched_parent_proof_instances{0};
    uint64_t family_batched_total_proof_instances{0};
    bool exact_schedule_manifest_derived{false};
    bool one_program_selector_per_family{false};
    bool parent_is_constant_width_universal_program{false};
    bool normalized_root_is_constant_width_program{false};
    bool width_shards_are_not_site_multiplicity{false};
    bool registry_is_root_pinnable{false};
    bool semantic_programs_complete{false};
    bool recursive_program_selection_executable{false};
    bool family_batched_single_quotient_fri_executable{false};
    bool family_batched_candidate_selectable{false};
    bool shard_tree_economically_production_candidate{false};
    bool production_topology_enforced{false};
    std::string note;
};

[[nodiscard]] UniversalTopologyAssessmentV1
AssessUniversalProductionTopologyV1(
    const sites::ProductionProofSiteManifest& manifest,
    const sched::ProductionAggregationSchedule& schedule,
    const ProductionProgramRegistryV1& registry);

/**
 * Exact selector absorbed by every leaf Fiat--Shamir statement. The program
 * and public-input schema are resolved from the root-pinned registry; callers
 * cannot supply a verifying key.
 */
struct UniversalLeafSelectorV1 {
    uint16_t version{kUniversalStatementVersionV1};
    uint256 unified_root_seed{};
    uint256 registry_external_commitment{};
    ah::Digest registry_recursive_commitment{};
    uint32_t family_index{0};
    uint64_t global_leaf_site{0};
    uint64_t family_local_site{0};
    uint256 public_input_commitment{};
    ah::Digest trace_commitment{};
};

struct UniversalStatementBindingV1 {
    uint256 external_sha256d{};
    ah::Digest recursive_alg_hash{};
    bool program_and_schema_resolved_from_registry{false};
    bool manifest_schedule_and_site_bound{false};
    bool public_inputs_bound{false};
};

[[nodiscard]] UniversalStatementBindingV1
BindUniversalLeafStatementV1(
    const sites::ProductionProofSiteManifest& manifest,
    const sched::ProductionAggregationSchedule& schedule,
    const ProductionProgramRegistryV1& registry,
    const UniversalLeafSelectorV1& selector,
    std::string* why = nullptr);

/**
 * Parent statements bind the canonical scheduler work seed, the one
 * registry-selected universal verifier, committed public inputs and the exact
 * ordered child receipt roots. A parent with omitted/reordered children has a
 * different statement.
 */
struct UniversalParentSelectorV1 {
    uint16_t version{kUniversalStatementVersionV1};
    uint256 unified_root_seed{};
    uint256 registry_external_commitment{};
    ah::Digest registry_recursive_commitment{};
    uint64_t parent_ordinal{0};
    uint256 public_input_commitment{};
    std::vector<ah::Digest> child_receipt_roots;
};

[[nodiscard]] UniversalStatementBindingV1
BindUniversalParentStatementV1(
    const sites::ProductionProofSiteManifest& manifest,
    const sched::ProductionAggregationSchedule& schedule,
    const ProductionProgramRegistryV1& registry,
    const UniversalParentSelectorV1& selector,
    std::string* why = nullptr);

/**
 * The 244+82 planner figures apply only to a rejected monolithic verifier.
 * They are neither added to nor multiplied by the canonical heterogeneous
 * schedule once the selected universal verifier is below the column cap.
 */
inline constexpr bool kWidthPlannerCountIsProofMultiplicityV1 = false;
static_assert(!kWidthPlannerCountIsProofMultiplicityV1);

} // namespace matmul::v4::rc::universal_topology

#endif
