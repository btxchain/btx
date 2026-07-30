// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BTX_MATMUL_MATMUL_V4_RC_STAGE3_RELATION_LOCAL_SHARDING_H
#define BTX_MATMUL_MATMUL_V4_RC_STAGE3_RELATION_LOCAL_SHARDING_H

#include <matmul/matmul_v4_rc_stage3_constraint_bytecode.h>
#include <uint256.h>

#include <array>
#include <cstdint>
#include <string>
#include <vector>

namespace matmul::v4::rc::stage3_relation_local_sharding {

inline constexpr uint16_t kRelationLocalShardManifestVersionV1 = 1;
inline constexpr uint32_t kRelationLocalShardColumnCapV1 = 512;
inline constexpr uint32_t kRelationLocalShardRecursionArityV1 = 4;
inline constexpr uint32_t kRelationLocalShardQueriesV1 = 192;
inline constexpr uint32_t kRelationLocalFp3BytesV1 = 24;

/**
 * Exact support of one canonical constraint-bytecode program. Current and
 * next-row loads refer to the same committed trace polynomial, so
 * `global_columns` is their sorted union. The two masks retain the evaluation
 * direction needed to audit projection.
 */
struct ConstraintSupportV1 {
    uint32_t ordinal{0};
    uint256 program_commitment{};
    air_quotient::AirKind kind{
        air_quotient::AirKind::kEverywhere};
    uint32_t declared_degree{0};
    std::vector<uint32_t> global_columns;
    std::vector<uint32_t> current_columns;
    std::vector<uint32_t> next_columns;

    bool operator==(const ConstraintSupportV1&) const = default;
};

/**
 * A shard owns each listed original constraint exactly once and commits the
 * sorted union of its trace-column support. `projected_table` is the original
 * SSA bytecode with Current/Next operands canonically remapped to local column
 * indices. It therefore proves the original relation, not an RLC surrogate.
 */
struct RelationLocalShardV1 {
    uint32_t index{0};
    std::vector<uint32_t> global_columns;
    std::vector<uint32_t> constraint_ordinals;
    constraint_bytecode::ProgramTable projected_table;
    uint256 projected_table_commitment{};

    bool operator==(const RelationLocalShardV1&) const = default;
};

/**
 * One duplicate-column equality obligation. The tuple is (row_index, value),
 * not merely value: multiset equality of values alone permits row
 * permutations. A production proof needs two post-commit Fp3 LogUp lanes and
 * must expose both terminal equalities to the recursive parent.
 */
struct CrossShardEqualityLinkV1 {
    uint32_t index{0};
    uint32_t global_column{0};
    uint32_t anchor_shard{0};
    uint32_t replica_shard{0};
    uint32_t anchor_local_column{0};
    uint32_t replica_local_column{0};
    uint32_t tuple_arity{2};
    uint32_t independent_lanes{2};
    bool row_index_tagged{true};
    bool challenges_after_all_shard_commitments{true};
    /** May become true only when both shards root-pin this global column to
     * one shared committed oracle. It is false in the current backend, so
     * the equality CTL remains mandatory. */
    bool discharged_by_shared_global_root{false};

    bool operator==(const CrossShardEqualityLinkV1&) const = default;
};

struct RelationLocalAggregationLevelV1 {
    uint32_t level{0};
    uint32_t input_receipts{0};
    uint32_t parent_receipts{0};

    bool operator==(const RelationLocalAggregationLevelV1&) const = default;
};

struct RelationLocalCostModelV1 {
    uint32_t trace_rows{0};
    uint32_t original_columns{0};
    uint32_t shard_count{0};
    uint32_t equality_link_count{0};
    uint32_t leaf_receipt_count{0};
    uint32_t recursive_parent_count{0};
    uint32_t recursive_levels{0};
    uint32_t maximum_shard_columns{0};
    uint64_t sharded_trace_cells{0};
    uint64_t sharded_trace_bytes{0};
    /**
     * Unavoidable current+next Fp3 values if a non-recursive verifier opens
     * every local column at Q points. Paths, FRI folds, framing and equality
     * proof payloads are excluded, so this is a lower bound.
     */
    uint64_t direct_opening_value_bytes_lower_bound{0};
    uint64_t root_verifier_target_micros{900000};
    uint64_t measured_root_verifier_micros{0};
    bool timing_measured{false};
    bool timing_target_met{false};

    bool operator==(const RelationLocalCostModelV1&) const = default;
};

struct RelationLocalShardManifestV1 {
    uint16_t version{kRelationLocalShardManifestVersionV1};
    bool valid{false};
    std::string note;
    RCStage3RelationRole role{};
    uint32_t trace_rows{0};
    uint32_t original_columns{0};
    uint32_t original_constraints{0};
    uint32_t maximum_shard_columns{
        kRelationLocalShardColumnCapV1};
    uint256 original_program_table_commitment{};
    uint256 manifest_commitment{};
    std::vector<ConstraintSupportV1> supports;
    std::vector<RelationLocalShardV1> shards;
    std::vector<CrossShardEqualityLinkV1> equality_links;
    std::vector<RelationLocalAggregationLevelV1>
        aggregation_levels;
    RelationLocalCostModelV1 cost;

    bool all_constraints_explicit{false};
    bool exact_constraint_partition{false};
    bool exact_column_projection{false};
    bool quotient_conjunction_equivalent{false};
    /** Shard column maps already use canonical global column ids, allowing a
     * future backend to commit each global oracle once instead of cloning it
     * into shard-local commitments. */
    bool shared_global_column_ids_explicit{false};
    /** False until the proof codec and verifier actually root-pin every
     * projected local column to the common global commitment. */
    bool shared_global_column_roots_bound{false};
    /** False until the error of every leaf, equality proof and recursive
     * parent is composed (at minimum by a union bound) against the global
     * post-PoW target. */
    bool global_soundness_composition_proved{false};
    bool backend_leaf_shape_supported{false};
    bool equality_ctl_proofs_executable{false};
    bool equality_terminals_recursively_consumed{false};
    bool normalized_arity_four_parent_executable{false};
    bool production_authority_ready{false};

    bool operator==(const RelationLocalShardManifestV1&) const = default;
};

/**
 * Phase-separated equality construction for one relation-local shard.
 *
 * The relation columns remain in SplitRAP R0.  For every incident duplicate
 * column, the CTL VALUE is a literal reference to that local relation column;
 * there is no prover-supplied mirror vector.  After every ordered shard R0
 * root is committed, the coordinator derives the two (gamma,alpha) lanes.
 * Six challenge-dependent columns per incident link (INV1/2, TERM1/2,
 * RUN1/2) then live in Rdep.  This avoids both an FS fixed point and an
 * unbound cross-proof column root.
 */
struct EmbeddedCtlShardPlanV1 {
    uint32_t shard_index{0};
    std::vector<uint32_t> incident_link_indices;
    uint32_t relation_base_columns{0};
    uint32_t ctl_dependent_columns{0};
    uint32_t augmented_trace_columns{0};
    uint32_t exported_terminal_cells{0};

    bool operator==(const EmbeddedCtlShardPlanV1&) const = default;
};

struct RelationLocalEmbeddedCtlPlanV1 {
    uint16_t version{1};
    bool valid{false};
    std::string note;
    uint256 shard_manifest_commitment{};
    uint256 coordinator_schedule_commitment{};
    uint32_t ordered_phase0_roots{0};
    uint32_t equality_links{0};
    uint32_t value_direct_aliases{0};
    uint32_t dependent_ctl_columns{0};
    uint32_t exported_terminal_cells{0};
    uint32_t maximum_augmented_shard_columns{0};
    uint32_t split_rap_leaf_proofs{0};
    uint32_t arity_four_parent_proofs{0};
    uint32_t arity_four_levels{0};
    uint32_t recursively_consumed_equality_links{0};
    uint32_t recursively_consumed_leaf_proofs{0};
    bool all_values_directly_alias_relation_columns{false};
    bool all_base_roots_precede_challenges{false};
    bool dual_lanes_domain_separated{false};
    bool degree_two_n_coeffs_equal_trace_rows{false};
    bool split_rap_shape_compatible{false};
    /** False until the application-specific augmented AIR builder emits and
     * verifies these constraints, rather than merely scheduling them. */
    bool augmented_child_proof_builder_executable{false};
    /** False until V_CS checks the complete child proof and CTL terminal
     * cancellation inside the normalized parent AIR. */
    bool normalized_parent_verifier_executable{false};
    bool recursive_consumption_complete{false};
    std::vector<EmbeddedCtlShardPlanV1> shards;

    bool operator==(const RelationLocalEmbeddedCtlPlanV1&) const = default;
};

[[nodiscard]] RelationLocalEmbeddedCtlPlanV1
BuildRelationLocalEmbeddedCtlPlanV1(
    const RelationLocalShardManifestV1& manifest);

[[nodiscard]] bool ValidateRelationLocalEmbeddedCtlPlanV1(
    const RelationLocalShardManifestV1& manifest,
    const RelationLocalEmbeddedCtlPlanV1& plan,
    std::string* why = nullptr);

/**
 * Build the canonical hypergraph partition for one fully explicit role. The
 * deterministic greedy rule processes constraints in ordinal order and picks
 * the fitting shard with maximum support overlap (lowest index on ties).
 */
[[nodiscard]] RelationLocalShardManifestV1
BuildRelationLocalShardManifestV1(
    const constraint_bytecode::ProgramTable& table,
    uint32_t trace_rows,
    uint32_t maximum_shard_columns =
        kRelationLocalShardColumnCapV1);

/** Rebuild-and-compare validation; omission, reorder and counter promotion
 * fail closed. */
[[nodiscard]] bool ValidateRelationLocalShardManifestV1(
    const constraint_bytecode::ProgramTable& table,
    const RelationLocalShardManifestV1& manifest,
    std::string* why = nullptr);

/**
 * Current production-candidate audit. This is deliberately separate from the
 * per-role builder because the 124,802-column number is a planner estimate,
 * not an executable ProgramTable. It records only defensible lower bounds.
 */
struct CurrentRelationLocalProductionAuditV1 {
    uint16_t version{kRelationLocalShardManifestVersionV1};
    bool valid{false};
    std::string note;
    uint32_t declared_trace_rows{256};
    uint32_t declared_columns{124802};
    uint32_t maximum_shard_columns{
        kRelationLocalShardColumnCapV1};
    uint32_t required_roles{14};
    uint32_t fully_migrated_roles{0};
    uint32_t partially_migrated_roles{0};
    uint32_t unmigrated_roles{0};
    uint32_t roles_with_opaque_callbacks{0};
    uint32_t exact_support_columns{0};
    /**
     * Sum of the disjoint, role-local ProgramTable namespaces.  This counts
     * every table column (including a verifier-owned or currently-unused
     * column), whereas exact_support_columns counts only Current/Next loads
     * reached by canonical bytecode.
     */
    uint32_t exact_namespace_columns{0};
    uint32_t explicit_local_program_tables{0};
    uint32_t explicit_local_constraints{0};
    uint32_t explicit_local_shards{0};
    uint32_t explicit_local_equality_links{0};
    /** Exact leaf+arity-four-parent instances obtained by running the
     * relation-local partitioner on every executable ProgramTable. This is
     * deliberately local-table topology, not the still-unavailable global
     * production schedule multiplicity. */
    uint32_t explicit_local_proof_instances{0};
    /** Exact local-table proof instances belonging to endpoint relations
     * whose producer provenance is already terminal and executable. */
    uint32_t semantically_complete_local_proof_instances{0};
    uint32_t shard_count_lower_bound{0};
    uint32_t recursive_parent_count_lower_bound{0};
    uint32_t recursive_levels_lower_bound{0};
    uint32_t proof_instances_lower_bound{0};
    uint32_t conservative_union_bound_loss_bits{0};
    uint32_t known_recursive_bits_integer{95};
    uint32_t conservative_global_bits_upper_bound{0};
    uint32_t required_per_proof_bits_for_100_global{0};
    bool declared_width_manifest_derived{false};
    bool partial_support_hypergraph_available{false};
    bool exact_support_hypergraph_available{false};
    bool recursive_program_commitments_available{false};
    bool cross_hash_program_commitment_binding_proved{false};
    /** False: 326 is a width-only planner estimate, not a count multiplied
     * by global/role/endpoint/scheduled-site topology. */
    bool proof_instance_multiplicity_manifest_derived{false};
    uint64_t manifest_derived_global_proof_instances{0};
    uint64_t manifest_derived_scheduled_proof_instances{0};
    bool all_registered_constraints_explicit{false};
    bool all_cross_shard_equalities_executable{false};
    bool normalized_recursive_parent_executable{false};
    bool global_soundness_composition_proved{false};
    bool production_root_timing_measured{false};
    bool sub_900ms_root_verified{false};
    bool production_candidate{false};

    struct CanonicalFamilySupportV1 {
        std::string family;
        RCStage3RelationRole role{};
        /** Zero for role infrastructure; otherwise a Stage-3 endpoint ABI id. */
        uint16_t mapped_endpoint{0};
        uint32_t role_namespace_base{0};
        uint32_t namespace_width{0};
        uint32_t exact_support_columns{0};
        uint32_t constraints{0};
        uint32_t shards{0};
        uint32_t equality_links{0};
        uint32_t leaf_receipts{0};
        uint32_t recursive_parents{0};
        uint32_t exact_proof_instances{0};
        bool proof_instance_shape_manifest_derived{false};
        uint256 program_table_commitment{};
        alg_hash::Digest recursive_program_table_commitment{};
        bool external_and_recursive_commitments_share_bytes{false};
        bool cross_hash_collision_binding_proved{false};
        /** Helper bytecode is not promoted to endpoint closure. */
        bool semantic_endpoint_complete{false};
        std::string residual;

        bool operator==(
            const CanonicalFamilySupportV1&) const = default;
    };

    struct RoleSupportTopologyV1 {
        RCStage3RelationRole role{};
        uint16_t first_endpoint{0};
        uint16_t semantic_endpoint_families{0};
        uint16_t semantically_complete_endpoint_families{0};
        uint16_t residual_opaque_semantic_families{0};
        uint32_t canonical_program_tables{0};
        uint32_t canonical_constraints{0};
        uint32_t role_namespace_columns{0};
        uint32_t exact_support_columns{0};
        uint32_t exact_shards{0};
        uint32_t exact_equality_links{0};
        /** Sorted ids in the concatenated, role-local table namespace. */
        std::vector<uint32_t> support_union;
        std::vector<CanonicalFamilySupportV1> canonical_families;
        bool namespace_derived_from_executable_bytecode{false};
        bool semantic_role_complete{false};

        bool operator==(
            const RoleSupportTopologyV1&) const = default;
    };

    uint16_t registered_semantic_endpoint_families{0};
    uint16_t semantically_complete_endpoint_families{0};
    uint16_t residual_opaque_semantic_families{0};
    std::vector<RoleSupportTopologyV1> role_support_topology;

    bool operator==(
        const CurrentRelationLocalProductionAuditV1&) const = default;
};

[[nodiscard]] CurrentRelationLocalProductionAuditV1
AssessCurrentRelationLocalProductionAuditV1();

[[nodiscard]] bool ValidateCurrentRelationLocalProductionAuditV1(
    const CurrentRelationLocalProductionAuditV1& audit,
    std::string* why = nullptr);

inline constexpr bool kRelationLocalShardingProductionAuthorityV1 = false;
static_assert(!kRelationLocalShardingProductionAuthorityV1);

} // namespace matmul::v4::rc::stage3_relation_local_sharding

#endif
