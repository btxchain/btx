// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BTX_MATMUL_MATMUL_V4_RC_STAGE3_AGGREGATION_SCHEDULE_H
#define BTX_MATMUL_MATMUL_V4_RC_STAGE3_AGGREGATION_SCHEDULE_H

#include <matmul/matmul_v4_rc_stage3_soundness_scenarios.h>

#include <cstdint>
#include <functional>
#include <optional>
#include <string>
#include <vector>

namespace matmul::v4::rc::aggregation_scheduler {

inline constexpr uint16_t kProductionAggregationScheduleVersion = 1;
inline constexpr uint8_t kProductionAggregationScheduleArity = 4;
inline constexpr uint16_t kBinaryV1AggregationScheduleVersion = 2;
inline constexpr uint8_t kBinaryV1AggregationScheduleArity = 2;

/**
 * One exact contiguous range in the global relation-leaf namespace.
 * `first_role_leaf` is the corresponding offset within the role's leaf
 * stream.  The canonical 28-family manifest determines these ranges without
 * enumerating any individual leaf.
 */
struct FamilyLeafRange {
    soundness_scenarios::ProductionProofSiteKind kind{};
    RCStage3RelationRole role{};
    uint32_t family_index{0};
    uint64_t first_leaf_site{0};
    uint64_t leaf_count{0};
    uint64_t first_role_leaf{0};

    bool operator==(const FamilyLeafRange&) const = default;
};

/**
 * One complete arity-four reduction level for a single role.  Both child and
 * parent site ranges are contiguous.  The last parent may have 1, 2 or 3
 * children when the previous level is not divisible by four.  Such a node is
 * still an explicitly charged proof site; it may not be silently elided.
 */
struct RoleAggregationLevel {
    uint32_t level{0};
    uint64_t first_child_site{0};
    uint64_t child_count{0};
    uint64_t first_parent_site{0};
    uint64_t parent_count{0};

    bool operator==(const RoleAggregationLevel&) const = default;
};

struct RoleAggregationPlan {
    RCStage3RelationRole role{};
    uint64_t first_leaf_site{0};
    uint64_t leaf_count{0};
    uint64_t root_site{0};
    std::vector<RoleAggregationLevel> levels;

    bool operator==(const RoleAggregationPlan&) const = default;
};

/**
 * Verifier-recomputable compact schedule for every below-root production
 * aggregation node.  The fixed normalized binary-16 tree is deliberately not
 * repeated here; its fifteen nodes remain committed by unified-root V3.
 */
struct ProductionAggregationSchedule {
    uint16_t version{kProductionAggregationScheduleVersion};
    uint8_t arity{kProductionAggregationScheduleArity};
    uint256 manifest_commitment{};
    uint64_t relation_leaf_sites{0};
    uint64_t below_root_parent_sites{0};
    uint64_t final_tree_parent_sites{0};
    uint64_t total_proof_sites{0};
    std::vector<FamilyLeafRange> families;
    std::vector<RoleAggregationPlan> roles;
    uint256 commitment{};

    bool operator==(const ProductionAggregationSchedule&) const = default;
};

[[nodiscard]] ProductionAggregationSchedule
BuildProductionAggregationSchedule(
    const soundness_scenarios::ProductionProofSiteManifest& manifest);

[[nodiscard]] uint256 CommitProductionAggregationSchedule(
    const ProductionAggregationSchedule& schedule);

[[nodiscard]] bool ValidateProductionAggregationSchedule(
    const soundness_scenarios::ProductionProofSiteManifest& manifest,
    const ProductionAggregationSchedule& schedule,
    std::string* why = nullptr);

/**
 * Canonical V1 fallback topology: reuse the exact selected production leaf
 * inventory but reduce every role with binary parents.  This intentionally
 * differs from the arity-four production candidate so the existing full-wide
 * normalized verifier can execute all six V_CS families at every node.
 *
 * It is a scenario/implementation path, not the active unified-root format.
 */
[[nodiscard]] ProductionAggregationSchedule
BuildBinaryV1AggregationSchedule(
    const soundness_scenarios::ProductionProofSiteManifest& manifest);
[[nodiscard]] uint256 CommitBinaryV1AggregationSchedule(
    const ProductionAggregationSchedule& schedule);
[[nodiscard]] bool ValidateBinaryV1AggregationSchedule(
    const soundness_scenarios::ProductionProofSiteManifest& manifest,
    const ProductionAggregationSchedule& schedule,
    std::string* why = nullptr);

/**
 * One canonical parent job. `parent_ordinal` is zero-based over every
 * below-root parent, in role/level/index order.  `seed` binds the job to one
 * unified-root seed, the exact schedule, role, range, level, and global site.
 */
struct ParentWorkItem {
    uint64_t parent_ordinal{0};
    RCStage3RelationRole role{};
    uint32_t level{0};
    uint64_t parent_index{0};
    uint64_t parent_site{0};
    uint64_t first_child_site{0};
    uint8_t child_count{0};
    uint256 schedule_commitment{};
    uint256 seed{};

    bool operator==(const ParentWorkItem&) const = default;
};

[[nodiscard]] std::optional<ParentWorkItem>
ProductionAggregationParentWorkItem(
    const ProductionAggregationSchedule& schedule,
    const uint256& unified_root_seed,
    uint64_t parent_ordinal,
    std::string* why = nullptr);

[[nodiscard]] std::optional<ParentWorkItem>
BinaryV1AggregationParentWorkItem(
    const ProductionAggregationSchedule& schedule,
    const uint256& unified_root_seed,
    uint64_t parent_ordinal,
    std::string* why = nullptr);

struct BinaryV1SoundnessScenario {
    ProductionAggregationSchedule schedule;
    uint64_t exact_total_sites{0};
    uint64_t union_bound_cap{0};
    uint32_t union_bound_log2{0};
    soundness_scenarios::FriScenario exact_site_screen;
    soundness_scenarios::FriScenario cap_screen;
    bool every_parent_child_count_at_most_two{false};
    /** False: the wide V_CS is not a shape fixed point and its Q128 full-row
     * openings exceed the 16 MiB per-lane codec cap. */
    bool every_parent_full_wide_eligible{false};
    bool numeric_exact_site_target_met{false};
    bool numeric_cap_target_met{false};
    bool all_node_execution_complete{false};
    bool theorem_complete{false};
    bool authority_eligible{false};
    std::string note;
};

/** Recompute the binary site count and dual-Q128 independent-batching screen. */
[[nodiscard]] BinaryV1SoundnessScenario
AssessBinaryV1SoundnessScenario(
    const soundness_scenarios::ProductionProofSiteManifest& manifest);

/**
 * A callback cannot return an unbound opaque commitment.  It must echo the
 * canonical work seed and bind its produced parent through
 * CommitProductionAggregationReceipt.  This is structural scheduling, not a
 * recursive child-proof verifier.
 */
struct ParentReceipt {
    uint256 work_seed{};
    uint256 parent_commitment{};
    uint256 binding{};

    bool operator==(const ParentReceipt&) const = default;
};

[[nodiscard]] uint256 CommitProductionAggregationReceipt(
    const ParentWorkItem& work,
    const uint256& parent_commitment);

using ParentCallback =
    std::function<std::optional<ParentReceipt>(const ParentWorkItem& work,
                                               std::string* why)>;

/**
 * Hash-chained paging cursor. BeginProductionAggregationExecution is the only
 * canonical start.  Passing each returned cursor into the next call processes
 * a contiguous prefix without storing per-node receipts.
 */
struct ExecutionCursor {
    uint256 schedule_commitment{};
    uint256 unified_root_seed{};
    uint64_t next_parent_ordinal{0};
    uint256 receipt_chain{};
    uint256 cursor_binding{};
    bool complete{false};

    bool operator==(const ExecutionCursor&) const = default;
};

[[nodiscard]] ExecutionCursor BeginProductionAggregationExecution(
    const ProductionAggregationSchedule& schedule,
    const uint256& unified_root_seed);

[[nodiscard]] bool ExecuteProductionAggregationPage(
    const soundness_scenarios::ProductionProofSiteManifest& manifest,
    const ProductionAggregationSchedule& schedule,
    const ParentCallback& callback,
    uint64_t max_parents,
    ExecutionCursor& cursor,
    std::string* why = nullptr);

/**
 * This flag means exact manifest ranges and parent jobs are executable and
 * root-bindable.  It deliberately does not mean that the callback verifies a
 * recursive child proof.
 */
inline constexpr bool
    kProductionAggregationStructuralSchedulerExecutable = true;
inline constexpr bool
    kProductionAggregationCryptographicChildConsumptionReady = false;
inline constexpr bool kBinaryV1ScheduleScenarioExecutable = true;
inline constexpr bool kBinaryV1AllNodeExecutionComplete = false;

static_assert(kProductionAggregationStructuralSchedulerExecutable);
static_assert(!kProductionAggregationCryptographicChildConsumptionReady);
static_assert(kBinaryV1ScheduleScenarioExecutable);
static_assert(!kBinaryV1AllNodeExecutionComplete);

} // namespace matmul::v4::rc::aggregation_scheduler

#endif // BTX_MATMUL_MATMUL_V4_RC_STAGE3_AGGREGATION_SCHEDULE_H
