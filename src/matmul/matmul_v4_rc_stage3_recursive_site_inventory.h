// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BTX_MATMUL_MATMUL_V4_RC_STAGE3_RECURSIVE_SITE_INVENTORY_H
#define BTX_MATMUL_MATMUL_V4_RC_STAGE3_RECURSIVE_SITE_INVENTORY_H

#include <matmul/matmul_v4_rc_stage3_aggregation_schedule.h>

#include <cstdint>
#include <string>
#include <vector>

namespace matmul::v4::rc::recursive_site_inventory {

namespace scheduler = aggregation_scheduler;
namespace sites = soundness_scenarios;

inline constexpr uint16_t kRecursiveSiteInventoryVersion = 1;
inline constexpr uint64_t kRecursiveSiteProtocolHardCap =
    uint64_t{1} << 28;

/**
 * Mutually exclusive status of one immutable relation-family leaf range.
 *
 * `KnownLocalAwaitingRecursion` means the entire production family has an
 * executable local relation, but not that its normalized recursive parent
 * consumes it. The other two states are counted obligations, not executed
 * proof families.
 */
enum class RecursiveFamilyClosure : uint8_t {
    KnownLocalAwaitingRecursion = 1,
    MissingAllInstanceRelation = 2,
    MissingHashOrXofRelation = 3,
};

struct RecursiveFamilySiteStatus {
    sites::ProductionProofSiteKind kind{};
    RCStage3RelationRole role{};
    uint32_t family_index{0};
    uint64_t first_leaf_site{0};
    uint64_t leaf_sites{0};
    RecursiveFamilyClosure closure{
        RecursiveFamilyClosure::MissingAllInstanceRelation};
    bool complete_local_relation_executable{false};
    bool normalized_recursive_consumed{false};
    std::string residual;

    bool operator==(const RecursiveFamilySiteStatus&) const = default;
};

/**
 * Runtime-derived cap ledger over the canonical relation manifest and its
 * canonical recursive aggregation schedule.
 *
 * Counts are disjoint:
 *   local-awaiting-recursion leaves
 * + missing all-instance leaves
 * + missing hash/XOF leaves
 * + missing RAP parent sites
 * = authority_residual_sites.
 *
 * Today that residual equals every enumerated site because normalized
 * recursive consumption is still absent. `hard_cap_enforced_for_enumerated`
 * is intentionally narrower than `global_cap_enforced`.
 */
struct ProductionRecursiveSiteInventory {
    uint16_t version{kRecursiveSiteInventoryVersion};
    uint64_t hard_cap{0};
    uint256 relation_manifest_commitment{};
    uint256 aggregation_schedule_commitment{};
    std::vector<RecursiveFamilySiteStatus> families;

    uint32_t required_family_count{0};
    uint32_t enumerated_family_count{0};
    uint32_t known_local_family_count{0};
    uint32_t missing_all_instance_family_count{0};
    uint32_t missing_hash_xof_family_count{0};

    uint64_t enumerated_relation_leaf_sites{0};
    uint64_t known_local_leaf_sites{0};
    uint64_t missing_all_instance_leaf_sites{0};
    uint64_t missing_hash_xof_leaf_sites{0};
    uint64_t below_root_aggregation_sites{0};
    uint64_t final_tree_aggregation_sites{0};
    uint64_t missing_rap_parent_sites{0};
    uint64_t enumerated_total_sites{0};
    uint64_t normalized_recursive_consumed_sites{0};
    uint64_t authority_residual_sites{0};

    bool checked_arithmetic{false};
    bool every_required_family_enumerated{false};
    bool family_ranges_match_immutable_schedule{false};
    bool hard_cap_check_executed{false};
    bool enumerated_schedule_within_hard_cap{false};
    bool hard_cap_enforced_for_enumerated_schedule{false};
    bool every_leaf_relation_complete{false};
    bool normalized_recursive_consumption_complete{false};
    bool global_cap_enforced{false};
    uint256 commitment{};

    bool operator==(const ProductionRecursiveSiteInventory&) const = default;
};

[[nodiscard]] ProductionRecursiveSiteInventory
BuildProductionRecursiveSiteInventory(
    const sites::ProductionProofSiteManifest& manifest,
    const scheduler::ProductionAggregationSchedule& schedule,
    uint64_t hard_cap = kRecursiveSiteProtocolHardCap);

[[nodiscard]] uint256 CommitProductionRecursiveSiteInventory(
    const ProductionRecursiveSiteInventory& inventory);

[[nodiscard]] bool ValidateProductionRecursiveSiteInventory(
    const sites::ProductionProofSiteManifest& manifest,
    const scheduler::ProductionAggregationSchedule& schedule,
    const ProductionRecursiveSiteInventory& inventory,
    std::string* why = nullptr);

/**
 * Runtime cap gate. It rejects invalid/omitted/overflowed manifests and an
 * otherwise canonical schedule whose exact total exceeds `hard_cap`.
 * Passing this gate does not imply global proof completeness.
 */
[[nodiscard]] bool EnforceProductionRecursiveSiteHardCap(
    const sites::ProductionProofSiteManifest& manifest,
    const scheduler::ProductionAggregationSchedule& schedule,
    uint64_t hard_cap,
    ProductionRecursiveSiteInventory* inventory = nullptr,
    std::string* why = nullptr);

} // namespace matmul::v4::rc::recursive_site_inventory

#endif // BTX_MATMUL_MATMUL_V4_RC_STAGE3_RECURSIVE_SITE_INVENTORY_H
