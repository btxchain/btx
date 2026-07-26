// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <matmul/matmul_v4_rc_stage3_aggregation_schedule.h>

#include <hash.h>
#include <matmul/matmul_v4_rc_air_quotient.h>
#include <matmul/matmul_v4_rc_air_quotient_alg.h>
#include <matmul/matmul_v4_rc_fri_ext3_alg.h>

#include <algorithm>
#include <limits>

namespace matmul::v4::rc::aggregation_scheduler {
namespace {

constexpr char SCHEDULE_DOMAIN[] =
    "BTX_RC_STAGE3_PRODUCTION_AGGREGATION_SCHEDULE_V1";
constexpr char BINARY_V1_SCHEDULE_DOMAIN[] =
    "BTX_RC_STAGE3_BINARY_V1_AGGREGATION_SCHEDULE_V1";
constexpr char WORK_SEED_DOMAIN[] =
    "BTX_RC_STAGE3_PRODUCTION_AGGREGATION_WORK_V1";
constexpr char RECEIPT_DOMAIN[] =
    "BTX_RC_STAGE3_PRODUCTION_AGGREGATION_RECEIPT_V1";
constexpr char RECEIPT_CHAIN_START_DOMAIN[] =
    "BTX_RC_STAGE3_PRODUCTION_AGGREGATION_CHAIN_START_V1";
constexpr char RECEIPT_CHAIN_STEP_DOMAIN[] =
    "BTX_RC_STAGE3_PRODUCTION_AGGREGATION_CHAIN_STEP_V1";
constexpr char CURSOR_DOMAIN[] =
    "BTX_RC_STAGE3_PRODUCTION_AGGREGATION_CURSOR_V1";
constexpr char CONSUMED_PARENT_DOMAIN[] =
    "BTX_RC_STAGE3_PRODUCTION_AGGREGATION_CONSUMED_PARENT_V1";
constexpr char NODE_CONTEXT_PUB_DOMAIN[] =
    "BTX_RC_STAGE3_PRODUCTION_AGGREGATION_NODE_PUB_V1";
constexpr char NODE_CONTEXT_RECEIPT_DOMAIN[] =
    "BTX_RC_STAGE3_PRODUCTION_AGGREGATION_NODE_RECEIPT_V1";

bool Fail(std::string* why, const std::string& detail)
{
    if (why != nullptr) {
        *why = "stage3:aggregation_schedule:" + detail;
    }
    return false;
}

bool CheckedAdd(uint64_t a, uint64_t b, uint64_t& out)
{
    if (b > std::numeric_limits<uint64_t>::max() - a) return false;
    out = a + b;
    return true;
}

bool CheckedMul(uint64_t a, uint64_t b, uint64_t& out)
{
    if (a != 0 && b > std::numeric_limits<uint64_t>::max() / a) {
        return false;
    }
    out = a * b;
    return true;
}

uint64_t CeilDiv(uint64_t numerator, uint64_t denominator)
{
    return numerator / denominator +
           static_cast<uint64_t>(numerator % denominator != 0);
}

uint64_t NextPow2(uint64_t value)
{
    uint64_t out = 1;
    while (out < value) {
        if (out > (std::numeric_limits<uint64_t>::max() >> 1)) {
            return 0;
        }
        out <<= 1;
    }
    return out;
}

std::vector<RCStage3RelationRole> ProductionRoles()
{
    std::vector<RCStage3RelationRole> roles =
        RequiredRCStage3RelationRoles(RCStage3StatementKind::Composed);
    if (!roles.empty() &&
        roles.back() == RCStage3RelationRole::CompositionLink) {
        roles.pop_back();
    }
    return roles;
}

uint256 ReceiptChainStart(const ProductionAggregationSchedule& schedule,
                          const uint256& unified_root_seed)
{
    if (schedule.commitment.IsNull() || unified_root_seed.IsNull()) return {};
    HashWriter hash;
    hash << RECEIPT_CHAIN_START_DOMAIN;
    hash << schedule.commitment;
    hash << unified_root_seed;
    hash << schedule.below_root_parent_sites;
    return hash.GetHash();
}

uint256 CommitCursor(const ExecutionCursor& cursor)
{
    if (cursor.schedule_commitment.IsNull() ||
        cursor.unified_root_seed.IsNull() ||
        cursor.receipt_chain.IsNull()) {
        return {};
    }
    HashWriter hash;
    hash << CURSOR_DOMAIN;
    hash << cursor.schedule_commitment;
    hash << cursor.unified_root_seed;
    hash << cursor.next_parent_ordinal;
    hash << cursor.receipt_chain;
    hash << cursor.complete;
    return hash.GetHash();
}

} // namespace

ProductionAggregationSchedule BuildProductionAggregationSchedule(
    const soundness_scenarios::ProductionProofSiteManifest& manifest)
{
    using namespace soundness_scenarios;

    ProductionAggregationSchedule out;
    std::string manifest_why;
    if (!ValidateProductionProofSiteManifest(manifest, &manifest_why) ||
        manifest.policy !=
            SelectedProductionProofSitePolicy() ||
        manifest.policy.aggregation_arity !=
            kProductionAggregationScheduleArity ||
        manifest.entries.size() != 28 ||
        manifest.commitment.IsNull()) {
        return {};
    }

    out.manifest_commitment = manifest.commitment;
    out.relation_leaf_sites = manifest.relation_leaf_sites;
    out.below_root_parent_sites =
        manifest.below_root_aggregation_sites;
    out.final_tree_parent_sites =
        manifest.final_tree_aggregation_sites;
    out.total_proof_sites = manifest.total_proof_sites;
    out.families.reserve(manifest.entries.size());

    const std::vector<RCStage3RelationRole> roles = ProductionRoles();
    if (roles.size() != 14) return {};
    std::vector<uint64_t> role_leaf_counts(roles.size(), 0);
    std::vector<uint64_t> role_first_leaves(
        roles.size(), std::numeric_limits<uint64_t>::max());
    uint64_t leaf_cursor{0};
    for (size_t family_index = 0;
         family_index < manifest.entries.size();
         ++family_index) {
        const auto& entry = manifest.entries[family_index];
        const auto role_it =
            std::find(roles.begin(), roles.end(), entry.role);
        if (role_it == roles.end() || entry.proof_sites == 0) return {};
        const size_t role_index =
            static_cast<size_t>(std::distance(roles.begin(), role_it));
        if (role_first_leaves[role_index] ==
            std::numeric_limits<uint64_t>::max()) {
            role_first_leaves[role_index] = leaf_cursor;
        }
        out.families.push_back(
            {entry.kind,
             entry.role,
             static_cast<uint32_t>(family_index),
             leaf_cursor,
             entry.proof_sites,
             role_leaf_counts[role_index]});
        if (!CheckedAdd(
                role_leaf_counts[role_index],
                entry.proof_sites,
                role_leaf_counts[role_index]) ||
            !CheckedAdd(leaf_cursor, entry.proof_sites, leaf_cursor)) {
            return {};
        }
    }
    if (leaf_cursor != manifest.relation_leaf_sites) return {};

    // Canonical entry order must make each role one contiguous leaf interval.
    for (size_t role_index = 0; role_index < roles.size(); ++role_index) {
        if (role_leaf_counts[role_index] == 0 ||
            role_first_leaves[role_index] ==
                std::numeric_limits<uint64_t>::max()) {
            return {};
        }
        uint64_t role_end{0};
        if (!CheckedAdd(
                role_first_leaves[role_index],
                role_leaf_counts[role_index],
                role_end)) {
            return {};
        }
        for (const auto& family : out.families) {
            if (family.role != roles[role_index]) continue;
            uint64_t family_end{0};
            if (!CheckedAdd(
                    family.first_leaf_site,
                    family.leaf_count,
                    family_end) ||
                family.first_leaf_site <
                    role_first_leaves[role_index] ||
                family_end > role_end) {
                return {};
            }
        }
    }

    uint64_t parent_cursor = manifest.relation_leaf_sites;
    out.roles.reserve(roles.size());
    for (size_t role_index = 0; role_index < roles.size(); ++role_index) {
        RoleAggregationPlan role;
        role.role = roles[role_index];
        role.first_leaf_site = role_first_leaves[role_index];
        role.leaf_count = role_leaf_counts[role_index];

        uint64_t child_first = role.first_leaf_site;
        uint64_t child_count = role.leaf_count;
        uint32_t level{1};
        while (child_count > 1) {
            const uint64_t parent_count =
                CeilDiv(child_count, out.arity);
            if (parent_count == 0 ||
                level == std::numeric_limits<uint32_t>::max()) {
                return {};
            }
            role.levels.push_back(
                {level,
                 child_first,
                 child_count,
                 parent_cursor,
                 parent_count});
            child_first = parent_cursor;
            if (!CheckedAdd(
                    parent_cursor, parent_count, parent_cursor)) {
                return {};
            }
            child_count = parent_count;
            ++level;
        }
        role.root_site = child_first;
        out.roles.push_back(std::move(role));
    }

    uint64_t below_root_end{0};
    uint64_t total_end{0};
    if (!CheckedAdd(
            manifest.relation_leaf_sites,
            manifest.below_root_aggregation_sites,
            below_root_end) ||
        parent_cursor != below_root_end ||
        !CheckedAdd(
            below_root_end,
            manifest.final_tree_aggregation_sites,
            total_end) ||
        total_end != manifest.total_proof_sites) {
        return {};
    }

    out.commitment = CommitProductionAggregationSchedule(out);
    if (out.commitment.IsNull()) return {};
    return out;
}

uint256 CommitProductionAggregationSchedule(
    const ProductionAggregationSchedule& schedule)
{
    if (schedule.version != kProductionAggregationScheduleVersion ||
        schedule.arity != kProductionAggregationScheduleArity ||
        schedule.manifest_commitment.IsNull() ||
        schedule.relation_leaf_sites == 0 ||
        schedule.below_root_parent_sites == 0 ||
        schedule.final_tree_parent_sites == 0 ||
        schedule.total_proof_sites == 0 ||
        schedule.families.empty() || schedule.roles.empty()) {
        return {};
    }

    HashWriter hash;
    hash << SCHEDULE_DOMAIN;
    hash << schedule.version;
    hash << schedule.arity;
    hash << schedule.manifest_commitment;
    hash << schedule.relation_leaf_sites;
    hash << schedule.below_root_parent_sites;
    hash << schedule.final_tree_parent_sites;
    hash << schedule.total_proof_sites;
    hash << static_cast<uint32_t>(schedule.families.size());
    for (const auto& family : schedule.families) {
        hash << static_cast<uint8_t>(family.kind);
        hash << static_cast<uint16_t>(family.role);
        hash << family.family_index;
        hash << family.first_leaf_site;
        hash << family.leaf_count;
        hash << family.first_role_leaf;
    }
    hash << static_cast<uint32_t>(schedule.roles.size());
    for (const auto& role : schedule.roles) {
        hash << static_cast<uint16_t>(role.role);
        hash << role.first_leaf_site;
        hash << role.leaf_count;
        hash << role.root_site;
        hash << static_cast<uint32_t>(role.levels.size());
        for (const auto& level : role.levels) {
            hash << level.level;
            hash << level.first_child_site;
            hash << level.child_count;
            hash << level.first_parent_site;
            hash << level.parent_count;
        }
    }
    return hash.GetHash();
}

bool ValidateProductionAggregationSchedule(
    const soundness_scenarios::ProductionProofSiteManifest& manifest,
    const ProductionAggregationSchedule& schedule,
    std::string* why)
{
    const ProductionAggregationSchedule expected =
        BuildProductionAggregationSchedule(manifest);
    if (expected.commitment.IsNull()) {
        return Fail(why, "manifest_has_no_canonical_arity4_schedule");
    }
    if (schedule != expected ||
        schedule.commitment !=
            CommitProductionAggregationSchedule(schedule)) {
        return Fail(why, "noncanonical_or_substituted");
    }
    if (why != nullptr) {
        *why =
            "stage3:aggregation_schedule:structurally_complete_"
            "cryptographic_child_consumption_pending";
    }
    return true;
}

ProductionAggregationSchedule BuildBinaryV1AggregationSchedule(
    const soundness_scenarios::ProductionProofSiteManifest& manifest)
{
    using namespace soundness_scenarios;

    ProductionAggregationSchedule out;
    out.version = kBinaryV1AggregationScheduleVersion;
    out.arity = kBinaryV1AggregationScheduleArity;
    std::string manifest_why;
    if (!ValidateProductionProofSiteManifest(manifest, &manifest_why) ||
        manifest.entries.size() != 28 ||
        manifest.commitment.IsNull() ||
        manifest.relation_leaf_sites == 0 ||
        manifest.final_tree_aggregation_sites == 0) {
        return {};
    }

    out.manifest_commitment = manifest.commitment;
    out.relation_leaf_sites = manifest.relation_leaf_sites;
    out.final_tree_parent_sites =
        manifest.final_tree_aggregation_sites;
    out.families.reserve(manifest.entries.size());

    const std::vector<RCStage3RelationRole> roles =
        ProductionRoles();
    if (roles.size() != 14) return {};
    std::vector<uint64_t> role_leaf_counts(roles.size(), 0);
    std::vector<uint64_t> role_first_leaves(
        roles.size(), std::numeric_limits<uint64_t>::max());
    uint64_t leaf_cursor{0};
    for (size_t family_index = 0;
         family_index < manifest.entries.size();
         ++family_index) {
        const auto& entry = manifest.entries[family_index];
        const auto role_it =
            std::find(roles.begin(), roles.end(), entry.role);
        if (role_it == roles.end() || entry.proof_sites == 0) {
            return {};
        }
        const size_t role_index = static_cast<size_t>(
            std::distance(roles.begin(), role_it));
        if (role_first_leaves[role_index] ==
            std::numeric_limits<uint64_t>::max()) {
            role_first_leaves[role_index] = leaf_cursor;
        }
        out.families.push_back(
            {entry.kind,
             entry.role,
             static_cast<uint32_t>(family_index),
             leaf_cursor,
             entry.proof_sites,
             role_leaf_counts[role_index]});
        if (!CheckedAdd(
                role_leaf_counts[role_index],
                entry.proof_sites,
                role_leaf_counts[role_index]) ||
            !CheckedAdd(
                leaf_cursor, entry.proof_sites, leaf_cursor)) {
            return {};
        }
    }
    if (leaf_cursor != manifest.relation_leaf_sites) return {};

    uint64_t parent_cursor = manifest.relation_leaf_sites;
    out.roles.reserve(roles.size());
    for (size_t role_index = 0;
         role_index < roles.size(); ++role_index) {
        if (role_leaf_counts[role_index] == 0 ||
            role_first_leaves[role_index] ==
                std::numeric_limits<uint64_t>::max()) {
            return {};
        }
        RoleAggregationPlan role;
        role.role = roles[role_index];
        role.first_leaf_site = role_first_leaves[role_index];
        role.leaf_count = role_leaf_counts[role_index];

        uint64_t child_first = role.first_leaf_site;
        uint64_t child_count = role.leaf_count;
        uint32_t level = 1;
        while (child_count > 1) {
            const uint64_t parent_count =
                CeilDiv(child_count, out.arity);
            if (parent_count == 0 ||
                level == std::numeric_limits<uint32_t>::max()) {
                return {};
            }
            role.levels.push_back(
                {level, child_first, child_count,
                 parent_cursor, parent_count});
            child_first = parent_cursor;
            if (!CheckedAdd(
                    parent_cursor, parent_count,
                    parent_cursor)) {
                return {};
            }
            child_count = parent_count;
            ++level;
        }
        role.root_site = child_first;
        out.roles.push_back(std::move(role));
    }
    if (parent_cursor < out.relation_leaf_sites) return {};
    out.below_root_parent_sites =
        parent_cursor - out.relation_leaf_sites;
    if (!CheckedAdd(
            parent_cursor, out.final_tree_parent_sites,
            out.total_proof_sites)) {
        return {};
    }
    out.commitment = CommitBinaryV1AggregationSchedule(out);
    return out;
}

uint256 CommitBinaryV1AggregationSchedule(
    const ProductionAggregationSchedule& schedule)
{
    if (schedule.version !=
            kBinaryV1AggregationScheduleVersion ||
        schedule.arity != kBinaryV1AggregationScheduleArity ||
        schedule.manifest_commitment.IsNull() ||
        schedule.relation_leaf_sites == 0 ||
        schedule.below_root_parent_sites == 0 ||
        schedule.final_tree_parent_sites == 0 ||
        schedule.total_proof_sites == 0 ||
        schedule.families.empty() || schedule.roles.empty()) {
        return {};
    }

    HashWriter hash;
    hash << BINARY_V1_SCHEDULE_DOMAIN;
    hash << schedule.version;
    hash << schedule.arity;
    hash << schedule.manifest_commitment;
    hash << schedule.relation_leaf_sites;
    hash << schedule.below_root_parent_sites;
    hash << schedule.final_tree_parent_sites;
    hash << schedule.total_proof_sites;
    hash << static_cast<uint32_t>(schedule.families.size());
    for (const auto& family : schedule.families) {
        hash << static_cast<uint8_t>(family.kind);
        hash << static_cast<uint16_t>(family.role);
        hash << family.family_index;
        hash << family.first_leaf_site;
        hash << family.leaf_count;
        hash << family.first_role_leaf;
    }
    hash << static_cast<uint32_t>(schedule.roles.size());
    for (const auto& role : schedule.roles) {
        hash << static_cast<uint16_t>(role.role);
        hash << role.first_leaf_site;
        hash << role.leaf_count;
        hash << role.root_site;
        hash << static_cast<uint32_t>(role.levels.size());
        for (const auto& level : role.levels) {
            hash << level.level;
            hash << level.first_child_site;
            hash << level.child_count;
            hash << level.first_parent_site;
            hash << level.parent_count;
        }
    }
    return hash.GetHash();
}

bool ValidateBinaryV1AggregationSchedule(
    const soundness_scenarios::ProductionProofSiteManifest& manifest,
    const ProductionAggregationSchedule& schedule,
    std::string* why)
{
    const ProductionAggregationSchedule expected =
        BuildBinaryV1AggregationSchedule(manifest);
    if (expected.commitment.IsNull()) {
        return Fail(why, "manifest_has_no_canonical_binary_v1_schedule");
    }
    if (schedule != expected ||
        schedule.commitment !=
            CommitBinaryV1AggregationSchedule(schedule)) {
        return Fail(why, "binary_v1_noncanonical_or_substituted");
    }
    if (why != nullptr) {
        *why =
            "stage3:aggregation_schedule:binary_v1_exact_"
            "all_node_execution_pending";
    }
    return true;
}

BinaryV1SoundnessScenario AssessBinaryV1SoundnessScenario(
    const soundness_scenarios::ProductionProofSiteManifest& manifest)
{
    BinaryV1SoundnessScenario out;
    out.schedule = BuildBinaryV1AggregationSchedule(manifest);
    std::string why;
    if (!ValidateBinaryV1AggregationSchedule(
            manifest, out.schedule, &why)) {
        out.note = why;
        return out;
    }
    out.exact_total_sites = out.schedule.total_proof_sites;
    out.union_bound_cap = NextPow2(out.exact_total_sites);
    if (out.union_bound_cap == 0) {
        out.note = "stage3:aggregation_schedule:binary_v1_cap_overflow";
        return out;
    }
    uint64_t cap = out.union_bound_cap;
    while (cap > 1) {
        ++out.union_bound_log2;
        cap >>= 1;
    }
    out.exact_site_screen =
        soundness_scenarios::AssessFriScenario(
            "binary_v1_dual_fp3_q128_independent_exact_sites",
            2, 128, 3, 24,
            soundness_scenarios::BatchChallengeShape::
                IndependentCoefficients,
            out.exact_total_sites);
    out.cap_screen =
        soundness_scenarios::AssessFriScenario(
            "binary_v1_dual_fp3_q128_independent_cap",
            2, 128, 3, 24,
            soundness_scenarios::BatchChallengeShape::
                IndependentCoefficients,
            out.union_bound_cap);
    out.every_parent_child_count_at_most_two = true;
    // Checking every one of ~50M ordinals would defeat compact schedule
    // validation. Every full group has arity children and only the final
    // group of a level can be smaller, so level metadata is sufficient.
    for (const auto& role : out.schedule.roles) {
        for (const auto& level : role.levels) {
            const uint64_t last_children =
                level.child_count -
                (level.parent_count - 1) *
                    out.schedule.arity;
            if (level.parent_count == 0 ||
                last_children < 1 ||
                last_children >
                    kBinaryV1AggregationScheduleArity) {
                out.every_parent_child_count_at_most_two = false;
            }
        }
    }
    // Child count is necessary but not sufficient. The existing wide parent
    // grows with child width and its Q128 full-row opening payload exceeds the
    // hard codec cap before Merkle paths are included.
    out.every_parent_full_wide_eligible = false;
    out.numeric_exact_site_target_met =
        out.exact_site_screen.numeric_target_met;
    out.numeric_cap_target_met =
        out.cap_screen.numeric_target_met;
    out.all_node_execution_complete = false;
    out.theorem_complete = false;
    out.authority_eligible = false;
    out.note =
        "stage3:aggregation_schedule:binary_v1_numeric_screen_"
        "wide_codec_and_fixedpoint_rejected_vertical_parent_pending";
    return out;
}

std::optional<ParentWorkItem>
ProductionAggregationParentWorkItem(
    const ProductionAggregationSchedule& schedule,
    const uint256& unified_root_seed,
    uint64_t parent_ordinal,
    std::string* why)
{
    const uint256 expected_commitment =
        schedule.arity == kProductionAggregationScheduleArity
        ? CommitProductionAggregationSchedule(schedule)
        : CommitBinaryV1AggregationSchedule(schedule);
    if (schedule.commitment.IsNull() ||
        schedule.commitment != expected_commitment) {
        Fail(why, "bad_schedule_commitment");
        return std::nullopt;
    }
    if (unified_root_seed.IsNull()) {
        Fail(why, "null_unified_root_seed");
        return std::nullopt;
    }
    if (parent_ordinal >= schedule.below_root_parent_sites) {
        Fail(why, "parent_ordinal_out_of_range");
        return std::nullopt;
    }

    uint64_t ordinal_cursor{0};
    for (const auto& role : schedule.roles) {
        for (const auto& level : role.levels) {
            uint64_t ordinal_end{0};
            if (!CheckedAdd(
                    ordinal_cursor, level.parent_count, ordinal_end)) {
                Fail(why, "parent_ordinal_overflow");
                return std::nullopt;
            }
            if (parent_ordinal >= ordinal_end) {
                ordinal_cursor = ordinal_end;
                continue;
            }

            const uint64_t parent_index =
                parent_ordinal - ordinal_cursor;
            uint64_t child_offset{0};
            uint64_t first_child_site{0};
            uint64_t parent_site{0};
            if (!CheckedMul(
                    parent_index, schedule.arity, child_offset) ||
                !CheckedAdd(
                    level.first_child_site,
                    child_offset,
                    first_child_site) ||
                !CheckedAdd(
                    level.first_parent_site,
                    parent_index,
                    parent_site) ||
                child_offset >= level.child_count) {
                Fail(why, "parent_range_overflow");
                return std::nullopt;
            }
            const uint64_t remaining =
                level.child_count - child_offset;
            const uint8_t child_count = static_cast<uint8_t>(
                std::min<uint64_t>(schedule.arity, remaining));
            if (child_count < 1 ||
                child_count > schedule.arity) {
                Fail(why, "invalid_parent_child_count");
                return std::nullopt;
            }

            ParentWorkItem work;
            work.parent_ordinal = parent_ordinal;
            work.role = role.role;
            work.level = level.level;
            work.parent_index = parent_index;
            work.parent_site = parent_site;
            work.first_child_site = first_child_site;
            work.child_count = child_count;
            work.schedule_commitment = schedule.commitment;
            HashWriter hash;
            hash << WORK_SEED_DOMAIN;
            hash << unified_root_seed;
            hash << schedule.commitment;
            hash << schedule.manifest_commitment;
            hash << schedule.arity;
            hash << static_cast<uint16_t>(work.role);
            hash << work.level;
            hash << work.parent_index;
            hash << work.parent_site;
            hash << work.first_child_site;
            hash << work.child_count;
            work.seed = hash.GetHash();
            return work;
        }
    }
    Fail(why, "parent_ordinal_not_covered");
    return std::nullopt;
}

std::optional<ParentWorkItem>
BinaryV1AggregationParentWorkItem(
    const ProductionAggregationSchedule& schedule,
    const uint256& unified_root_seed,
    uint64_t parent_ordinal,
    std::string* why)
{
    if (schedule.version !=
            kBinaryV1AggregationScheduleVersion ||
        schedule.arity != kBinaryV1AggregationScheduleArity ||
        schedule.commitment !=
            CommitBinaryV1AggregationSchedule(schedule)) {
        Fail(why, "bad_binary_v1_schedule");
        return std::nullopt;
    }
    return ProductionAggregationParentWorkItem(
        schedule, unified_root_seed, parent_ordinal, why);
}

uint256 CommitProductionAggregationReceipt(
    const ParentWorkItem& work,
    const uint256& parent_commitment)
{
    if (work.seed.IsNull() || work.schedule_commitment.IsNull() ||
        parent_commitment.IsNull() ||
        work.child_count < 1 ||
        work.child_count > kProductionAggregationScheduleArity) {
        return {};
    }
    HashWriter hash;
    hash << RECEIPT_DOMAIN;
    hash << work.schedule_commitment;
    hash << work.seed;
    hash << work.parent_ordinal;
    hash << static_cast<uint16_t>(work.role);
    hash << work.level;
    hash << work.parent_index;
    hash << work.parent_site;
    hash << work.first_child_site;
    hash << work.child_count;
    hash << parent_commitment;
    return hash.GetHash();
}

ExecutionCursor BeginProductionAggregationExecution(
    const ProductionAggregationSchedule& schedule,
    const uint256& unified_root_seed)
{
    ExecutionCursor out;
    if (schedule.commitment.IsNull() || unified_root_seed.IsNull()) {
        return out;
    }
    out.schedule_commitment = schedule.commitment;
    out.unified_root_seed = unified_root_seed;
    out.receipt_chain =
        ReceiptChainStart(schedule, unified_root_seed);
    out.complete = schedule.below_root_parent_sites == 0;
    out.cursor_binding = CommitCursor(out);
    return out;
}

bool ExecuteProductionAggregationPage(
    const soundness_scenarios::ProductionProofSiteManifest& manifest,
    const ProductionAggregationSchedule& schedule,
    const ParentCallback& callback,
    uint64_t max_parents,
    ExecutionCursor& cursor,
    std::string* why)
{
    if (!ValidateProductionAggregationSchedule(
            manifest, schedule, why)) {
        return false;
    }
    if (!callback) return Fail(why, "missing_callback");
    if (max_parents == 0) return Fail(why, "zero_page_size");
    if (cursor.schedule_commitment != schedule.commitment ||
        cursor.unified_root_seed.IsNull() ||
        cursor.receipt_chain.IsNull() ||
        cursor.cursor_binding.IsNull() ||
        cursor.cursor_binding != CommitCursor(cursor) ||
        cursor.next_parent_ordinal >
            schedule.below_root_parent_sites ||
        cursor.complete !=
            (cursor.next_parent_ordinal ==
             schedule.below_root_parent_sites)) {
        return Fail(why, "invalid_cursor");
    }
    if (cursor.next_parent_ordinal == 0 &&
        cursor.receipt_chain !=
            ReceiptChainStart(
                schedule, cursor.unified_root_seed)) {
        return Fail(why, "invalid_start_cursor");
    }
    if (cursor.complete) {
        if (why != nullptr) {
            *why = "stage3:aggregation_schedule:already_complete";
        }
        return true;
    }

    const uint64_t available =
        schedule.below_root_parent_sites -
        cursor.next_parent_ordinal;
    const uint64_t count = std::min(max_parents, available);
    for (uint64_t i = 0; i < count; ++i) {
        const uint64_t ordinal = cursor.next_parent_ordinal;
        const auto work = ProductionAggregationParentWorkItem(
            schedule, cursor.unified_root_seed, ordinal, why);
        if (!work.has_value()) return false;
        std::optional<ParentReceipt> receipt =
            callback(*work, why);
        if (!receipt.has_value()) {
            return Fail(why, "callback_failed");
        }
        const uint256 expected_binding =
            CommitProductionAggregationReceipt(
                *work, receipt->parent_commitment);
        if (receipt->work_seed != work->seed ||
            expected_binding.IsNull() ||
            receipt->binding != expected_binding) {
            return Fail(why, "unbound_or_replayed_receipt");
        }

        HashWriter chain;
        chain << RECEIPT_CHAIN_STEP_DOMAIN;
        chain << cursor.receipt_chain;
        chain << receipt->binding;
        chain << ordinal;
        cursor.receipt_chain = chain.GetHash();
        ++cursor.next_parent_ordinal;
        cursor.complete =
            cursor.next_parent_ordinal ==
            schedule.below_root_parent_sites;
        cursor.cursor_binding = CommitCursor(cursor);
    }
    if (why != nullptr) {
        *why = cursor.complete
            ? "stage3:aggregation_schedule:structural_execution_complete_"
              "cryptographic_child_consumption_pending"
            : "stage3:aggregation_schedule:structural_execution_page_ok_"
              "cryptographic_child_consumption_pending";
    }
    return true;
}

// ===========================================================================
// Cryptographic child consumption.
// ===========================================================================

namespace {

namespace aq = air_quotient;
namespace gf = gkr_field;
namespace rpa = recursive_parent_air;

using AlgB3 = aq::AirFriBackendAlg<gf::Fp3>;

/** Deterministic field lane stream derived from a domain-separated digest. */
gf::Fp3 LaneFromDigest(const char* domain, const ParentWorkItem& work,
                       uint32_t lane)
{
    HashWriter hash;
    hash << domain;
    hash << work.schedule_commitment;
    hash << work.seed;
    hash << static_cast<uint16_t>(work.role);
    hash << work.level;
    hash << work.parent_index;
    hash << work.parent_site;
    hash << lane;
    const uint256 digest = hash.GetHash();
    const auto* raw = digest.begin();
    uint64_t words[3] = {0, 0, 0};
    for (int limb = 0; limb < 3; ++limb) {
        for (int byte = 0; byte < 8; ++byte) {
            words[limb] |= static_cast<uint64_t>(raw[limb * 8 + byte])
                           << (8 * byte);
        }
    }
    return gf::Fp3{gf::FromU64(words[0]), gf::FromU64(words[1]),
                   gf::FromU64(words[2])};
}

} // namespace

rpa::FourSlotNodeContextV1 CanonicalParentNodeContext(
    const ParentWorkItem& work)
{
    rpa::FourSlotNodeContextV1 ctx;
    ctx.level = work.level;
    // The schedule's parent_index is a 64-bit ordinal within the level; the
    // node-context index is the AIR's 32-bit position lane.  Both are
    // verifier-recomputable; the full 64-bit site is separately absorbed into
    // every pub/receipt lane below, so no distinct site can collide here.
    ctx.index = static_cast<uint32_t>(work.parent_index);
    for (uint32_t lane = 0; lane < rpa::kFourSlotPubLanesV1; ++lane) {
        ctx.pub[lane] =
            LaneFromDigest(NODE_CONTEXT_PUB_DOMAIN, work, lane);
    }
    for (uint32_t word = 0;
         word < rpa::Arity4FamilyReceiptLayoutV1::kChildRootWords; ++word) {
        ctx.parent_receipt_root[word] =
            LaneFromDigest(NODE_CONTEXT_RECEIPT_DOMAIN, work, word);
    }
    return ctx;
}

uint256 PackParentStatement(const alg_hash::Digest& statement)
{
    return Fri3AlgDigestToUint256(statement);
}

uint256 CommitConsumedParentStatement(const ParentWorkItem& work,
                                      const uint256& parent_statement)
{
    if (work.seed.IsNull() || work.schedule_commitment.IsNull() ||
        parent_statement.IsNull()) {
        return {};
    }
    HashWriter hash;
    hash << CONSUMED_PARENT_DOMAIN;
    hash << work.schedule_commitment;
    hash << work.seed;
    hash << work.parent_ordinal;
    hash << static_cast<uint16_t>(work.role);
    hash << work.level;
    hash << work.parent_index;
    hash << work.parent_site;
    hash << work.first_child_site;
    hash << work.child_count;
    hash << parent_statement;
    return hash.GetHash();
}

CryptographicChildConsumption ConsumeRealChildProofsForParent(
    const ParentWorkItem& work, const ParentChildProofBundle& bundle)
{
    CryptographicChildConsumption out;
    out.parent_ordinal = work.parent_ordinal;
    out.parent_site = work.parent_site;
    out.level = work.level;
    out.parent_index = work.parent_index;
    out.child_count = work.child_count;

    if (work.seed.IsNull() || work.schedule_commitment.IsNull()) {
        out.note = "unbound_work_item";
        return out;
    }
    // The four-slot self-similar primitive is exactly arity four.  A partial
    // parent (1..3 children, produced when a level is not divisible by four) is
    // an explicitly charged proof site that this consumption path cannot yet
    // execute; it fails closed rather than padding a slot with a duplicate.
    if (work.child_count != kProductionAggregationScheduleArity) {
        out.note = "partial_arity_parent_not_consumable";
        return out;
    }
    if (bundle.child_fs_seed.IsNull()) {
        out.note = "missing_child_fs_seed";
        return out;
    }
    if (bundle.child_cs.n_columns == 0 || bundle.child_cs.n_rows == 0 ||
        bundle.child_cs.constraints.empty()) {
        out.note = "empty_child_constraint_system";
        return out;
    }

    // ---- Stage 1: real, unmodified, standalone proof verification. --------
    for (uint32_t slot = 0; slot < kProductionAggregationScheduleArity;
         ++slot) {
        std::string vwhy;
        if (!aq::AirQuotientVerify<gf::Fp3, AlgB3>(
                bundle.child_cs, bundle.child_proofs[slot],
                bundle.child_fs_seed, &vwhy)) {
            out.child_verify_reject_reason =
                "slot" + std::to_string(slot) + ":" + vwhy;
            out.note = "child_proof_rejected_by_verifier";
            return out;
        }
        ++out.children_standalone_verified;
    }
    out.all_children_standalone_verified =
        out.children_standalone_verified ==
        kProductionAggregationScheduleArity;

    // ---- Stage 2: in-AIR consumption by the arity-4 parent V_CS. ----------
    const rpa::FourSlotNodeContextV1 ctx = CanonicalParentNodeContext(work);
    const alg_hash::Digest statement =
        rpa::ComputeFourSlotSelfSimilarParentStatementV1(
            bundle.child_cs, bundle.child_proofs, bundle.child_fs_seed, ctx);
    const rpa::FourSlotSelfSimilarCtlParentV1 parent =
        rpa::BuildFourSlotSelfSimilarCtlParentV1(
            bundle.child_cs, bundle.child_proofs, bundle.child_fs_seed, ctx,
            statement);

    out.all_children_verified_in_parent_air =
        parent.all_four_children_verified_in_parent_air;
    out.terminal_lanes_sourced_from_in_parent_verifier =
        parent.terminal_lanes_sourced_from_in_parent_verifier;
    out.four_child_roots_sourced_from_verifier_outputs =
        parent.four_child_roots_sourced_from_verifier_outputs;
    out.parent_statement_equals_child_aggregation =
        parent.parent_statement_equals_child_aggregation;
    out.self_similar_arity4_shape = parent.self_similar_arity4_shape;
    out.witness_violations = parent.witness_violations;
    out.parent_rows = parent.parent_rows;
    out.parent_columns = parent.parent_columns;
    out.vcs_columns = parent.vcs_columns;
    // GAP[8] is reported by the parent AIR itself and is false by construction.
    out.child_fiat_shamir_replayed_in_parent =
        parent.child_fiat_shamir_replayed_in_parent;

    if (!parent.valid || parent.witness_violations != 0 ||
        !parent.all_four_children_verified_in_parent_air ||
        !parent.terminal_lanes_sourced_from_in_parent_verifier ||
        !parent.four_child_roots_sourced_from_verifier_outputs ||
        !parent.parent_statement_equals_child_aggregation) {
        out.note = parent.note.empty() ? "parent_air_rejected" : parent.note;
        return out;
    }

    out.parent_statement = PackParentStatement(parent.computed_parent_statement);
    if (out.parent_statement.IsNull()) {
        out.note = "unpackable_parent_statement";
        return out;
    }
    out.parent_commitment =
        CommitConsumedParentStatement(work, out.parent_statement);
    if (out.parent_commitment.IsNull()) {
        out.note = "unbound_parent_commitment";
        return out;
    }

    out.valid = true;
    // Sound recursion additionally requires the child Fiat-Shamir transcript to
    // be replayed in-parent from a proof-independent role seed (GAP[8]).
    out.recursion_soundness_admissible =
        out.child_fiat_shamir_replayed_in_parent;
    out.note = out.recursion_soundness_admissible
        ? "cryptographic_child_consumption_ok"
        : "cryptographic_child_consumption_ok_child_fiat_shamir_replay_"
          "not_closed";
    return out;
}

ParentCallback MakeCryptographicChildConsumingParentCallback(
    const ChildProofSource& source,
    std::vector<CryptographicChildConsumption>* trace)
{
    return [source, trace](const ParentWorkItem& work, std::string* why)
               -> std::optional<ParentReceipt> {
        if (!source) {
            Fail(why, "missing_child_proof_source");
            return std::nullopt;
        }
        ParentChildProofBundle bundle;
        std::string source_why;
        if (!source(work, bundle, &source_why)) {
            Fail(why, "child_proof_source_failed:" + source_why);
            return std::nullopt;
        }
        const CryptographicChildConsumption consumed =
            ConsumeRealChildProofsForParent(work, bundle);
        if (trace != nullptr) trace->push_back(consumed);
        if (!consumed.valid) {
            Fail(why,
                 "child_consumption_rejected:" + consumed.note +
                     (consumed.child_verify_reject_reason.empty()
                          ? std::string{}
                          : ":" + consumed.child_verify_reject_reason));
            return std::nullopt;
        }
        ParentReceipt receipt;
        receipt.work_seed = work.seed;
        receipt.parent_commitment = consumed.parent_commitment;
        receipt.binding = CommitProductionAggregationReceipt(
            work, receipt.parent_commitment);
        if (receipt.binding.IsNull()) {
            Fail(why, "unbound_receipt");
            return std::nullopt;
        }
        return receipt;
    };
}

} // namespace matmul::v4::rc::aggregation_scheduler
