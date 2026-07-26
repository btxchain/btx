// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <matmul/matmul_v4_rc_stage3_recursive_site_inventory.h>

#include <hash.h>

#include <limits>
#include <utility>

namespace matmul::v4::rc::recursive_site_inventory {
namespace {

constexpr char INVENTORY_DOMAIN[] =
    "BTX_RC_STAGE3_RECURSIVE_SITE_INVENTORY_V1";

bool Fail(std::string* why, const std::string& detail)
{
    if (why != nullptr) {
        *why = "stage3:recursive_site_inventory:" + detail;
    }
    return false;
}

bool CheckedAdd(uint64_t a, uint64_t b, uint64_t& out)
{
    if (b > std::numeric_limits<uint64_t>::max() - a) return false;
    out = a + b;
    return true;
}

RecursiveFamilyClosure Classify(
    sites::ProductionProofSiteKind kind)
{
    using Kind = sites::ProductionProofSiteKind;
    switch (kind) {
    case Kind::EpisodeSignedRange:
        // The full production signed-range shard family executes locally.
        // Its parent proof is still not recursively consumed.
        return RecursiveFamilyClosure::KnownLocalAwaitingRecursion;

    case Kind::EpisodeBuilderCounterXof:
    case Kind::EpisodeScaleSha:
    case Kind::EpisodeExtractChaCha:
    case Kind::EpisodeTileTreeSha256d:
    case Kind::EpisodeDigestSha256d:
    case Kind::CoupledBankCounterXof:
    case Kind::CoupledBankCommitmentSha256d:
    case Kind::CoupledLobeInitCounterXof:
    case Kind::CoupledPageScheduleXof:
    case Kind::CoupledExchangeXof:
    case Kind::CoupledPermutationXof:
    case Kind::CoupledMixXof:
    case Kind::CoupledExtractScaleSha:
    case Kind::CoupledExtractChaCha:
    case Kind::CoupledBarrierSha256d:
    case Kind::CoupledDigestSha256d:
        return RecursiveFamilyClosure::MissingHashOrXofRelation;

    case Kind::EpisodeGemmSumcheck:
    case Kind::EpisodeGemmOpenings:
    case Kind::EpisodeRangeExtractCtl:
    case Kind::EpisodeExtractCore:
    case Kind::EpisodeWiring:
    case Kind::CoupledBank:
    case Kind::CoupledGemm:
    case Kind::CoupledExchange:
    case Kind::CoupledPermutation:
    case Kind::CoupledMix:
    case Kind::CoupledExtractCore:
        return RecursiveFamilyClosure::MissingAllInstanceRelation;
    }
    return RecursiveFamilyClosure::MissingAllInstanceRelation;
}

const char* Residual(RecursiveFamilyClosure closure)
{
    switch (closure) {
    case RecursiveFamilyClosure::KnownLocalAwaitingRecursion:
        return "local relation complete; normalized RAP child consumption "
               "missing";
    case RecursiveFamilyClosure::MissingAllInstanceRelation:
        return "production all-instance/all-tile relation or provenance "
               "closure missing";
    case RecursiveFamilyClosure::MissingHashOrXofRelation:
        return "production hash/XOF relation or its recursive equality link "
               "missing";
    }
    return "unclassified production family";
}

bool AddTo(uint64_t value, uint64_t& accumulator)
{
    return CheckedAdd(accumulator, value, accumulator);
}

} // namespace

ProductionRecursiveSiteInventory
BuildProductionRecursiveSiteInventory(
    const sites::ProductionProofSiteManifest& manifest,
    const scheduler::ProductionAggregationSchedule& schedule,
    uint64_t hard_cap)
{
    ProductionRecursiveSiteInventory out;
    out.hard_cap = hard_cap;
    out.required_family_count = 28;
    out.relation_manifest_commitment = manifest.commitment;
    out.aggregation_schedule_commitment = schedule.commitment;

    std::string why;
    if (hard_cap == 0 ||
        !sites::ValidateProductionProofSiteManifest(
            manifest, &why) ||
        !scheduler::ValidateProductionAggregationSchedule(
            manifest, schedule, &why)) {
        return out;
    }

    out.enumerated_family_count =
        static_cast<uint32_t>(schedule.families.size());
    out.families.reserve(schedule.families.size());
    bool arithmetic_ok = true;
    uint8_t expected_kind = 1;
    for (const auto& family : schedule.families) {
        if (family.family_index >= manifest.entries.size()) {
            return {};
        }
        const auto& entry = manifest.entries[family.family_index];
        if (entry.kind != family.kind ||
            entry.role != family.role ||
            entry.proof_sites != family.leaf_count ||
            static_cast<uint8_t>(family.kind) != expected_kind) {
            return {};
        }
        ++expected_kind;

        RecursiveFamilySiteStatus status;
        status.kind = family.kind;
        status.role = family.role;
        status.family_index = family.family_index;
        status.first_leaf_site = family.first_leaf_site;
        status.leaf_sites = family.leaf_count;
        status.closure = Classify(family.kind);
        status.complete_local_relation_executable =
            status.closure ==
            RecursiveFamilyClosure::KnownLocalAwaitingRecursion;
        status.normalized_recursive_consumed = false;
        status.residual = Residual(status.closure);

        arithmetic_ok &=
            AddTo(
                status.leaf_sites,
                out.enumerated_relation_leaf_sites);
        switch (status.closure) {
        case RecursiveFamilyClosure::KnownLocalAwaitingRecursion:
            ++out.known_local_family_count;
            arithmetic_ok &=
                AddTo(status.leaf_sites, out.known_local_leaf_sites);
            break;
        case RecursiveFamilyClosure::MissingAllInstanceRelation:
            ++out.missing_all_instance_family_count;
            arithmetic_ok &=
                AddTo(
                    status.leaf_sites,
                    out.missing_all_instance_leaf_sites);
            break;
        case RecursiveFamilyClosure::MissingHashOrXofRelation:
            ++out.missing_hash_xof_family_count;
            arithmetic_ok &=
                AddTo(
                    status.leaf_sites,
                    out.missing_hash_xof_leaf_sites);
            break;
        }
        if (!arithmetic_ok) return {};
        out.families.push_back(std::move(status));
    }

    out.every_required_family_enumerated =
        out.enumerated_family_count == out.required_family_count &&
        manifest.entries.size() == out.required_family_count &&
        expected_kind == out.required_family_count + 1;
    out.family_ranges_match_immutable_schedule =
        out.enumerated_relation_leaf_sites ==
        schedule.relation_leaf_sites;
    out.below_root_aggregation_sites =
        schedule.below_root_parent_sites;
    out.final_tree_aggregation_sites =
        schedule.final_tree_parent_sites;
    if (!CheckedAdd(
            out.below_root_aggregation_sites,
            out.final_tree_aggregation_sites,
            out.missing_rap_parent_sites) ||
        !CheckedAdd(
            out.enumerated_relation_leaf_sites,
            out.missing_rap_parent_sites,
            out.enumerated_total_sites) ||
        !CheckedAdd(
            out.missing_all_instance_leaf_sites,
            out.missing_hash_xof_leaf_sites,
            out.authority_residual_sites) ||
        !CheckedAdd(
            out.authority_residual_sites,
            out.known_local_leaf_sites,
            out.authority_residual_sites) ||
        !CheckedAdd(
            out.authority_residual_sites,
            out.missing_rap_parent_sites,
            out.authority_residual_sites)) {
        return {};
    }
    if (out.enumerated_total_sites != schedule.total_proof_sites ||
        out.authority_residual_sites != out.enumerated_total_sites) {
        return {};
    }

    out.checked_arithmetic = arithmetic_ok;
    out.hard_cap_check_executed = true;
    out.enumerated_schedule_within_hard_cap =
        out.enumerated_total_sites <= hard_cap;
    out.hard_cap_enforced_for_enumerated_schedule =
        out.checked_arithmetic &&
        out.every_required_family_enumerated &&
        out.family_ranges_match_immutable_schedule &&
        out.enumerated_schedule_within_hard_cap;

    out.normalized_recursive_consumed_sites = 0;
    out.every_leaf_relation_complete =
        out.missing_all_instance_family_count == 0 &&
        out.missing_hash_xof_family_count == 0;
    out.normalized_recursive_consumption_complete =
        out.normalized_recursive_consumed_sites ==
            out.enumerated_total_sites &&
        out.missing_rap_parent_sites == 0;
    out.global_cap_enforced =
        out.hard_cap_enforced_for_enumerated_schedule &&
        out.every_leaf_relation_complete &&
        out.normalized_recursive_consumption_complete &&
        out.authority_residual_sites == 0;

    out.commitment =
        CommitProductionRecursiveSiteInventory(out);
    if (out.commitment.IsNull()) return {};
    return out;
}

uint256 CommitProductionRecursiveSiteInventory(
    const ProductionRecursiveSiteInventory& inventory)
{
    if (inventory.version != kRecursiveSiteInventoryVersion ||
        inventory.hard_cap == 0 ||
        inventory.relation_manifest_commitment.IsNull() ||
        inventory.aggregation_schedule_commitment.IsNull() ||
        inventory.families.empty() ||
        !inventory.checked_arithmetic ||
        !inventory.every_required_family_enumerated ||
        !inventory.family_ranges_match_immutable_schedule ||
        !inventory.hard_cap_check_executed ||
        inventory.enumerated_total_sites == 0) {
        return {};
    }
    HashWriter hash;
    hash << INVENTORY_DOMAIN;
    hash << inventory.version;
    hash << inventory.hard_cap;
    hash << inventory.relation_manifest_commitment;
    hash << inventory.aggregation_schedule_commitment;
    hash << inventory.required_family_count;
    hash << inventory.enumerated_family_count;
    hash << static_cast<uint32_t>(inventory.families.size());
    for (const auto& family : inventory.families) {
        hash << static_cast<uint8_t>(family.kind);
        hash << static_cast<uint16_t>(family.role);
        hash << family.family_index;
        hash << family.first_leaf_site;
        hash << family.leaf_sites;
        hash << static_cast<uint8_t>(family.closure);
        hash << family.complete_local_relation_executable;
        hash << family.normalized_recursive_consumed;
        hash << family.residual;
    }
    hash << inventory.known_local_family_count;
    hash << inventory.missing_all_instance_family_count;
    hash << inventory.missing_hash_xof_family_count;
    hash << inventory.enumerated_relation_leaf_sites;
    hash << inventory.known_local_leaf_sites;
    hash << inventory.missing_all_instance_leaf_sites;
    hash << inventory.missing_hash_xof_leaf_sites;
    hash << inventory.below_root_aggregation_sites;
    hash << inventory.final_tree_aggregation_sites;
    hash << inventory.missing_rap_parent_sites;
    hash << inventory.enumerated_total_sites;
    hash << inventory.normalized_recursive_consumed_sites;
    hash << inventory.authority_residual_sites;
    hash << inventory.checked_arithmetic;
    hash << inventory.every_required_family_enumerated;
    hash << inventory.family_ranges_match_immutable_schedule;
    hash << inventory.hard_cap_check_executed;
    hash << inventory.enumerated_schedule_within_hard_cap;
    hash << inventory.hard_cap_enforced_for_enumerated_schedule;
    hash << inventory.every_leaf_relation_complete;
    hash << inventory.normalized_recursive_consumption_complete;
    hash << inventory.global_cap_enforced;
    return hash.GetHash();
}

bool ValidateProductionRecursiveSiteInventory(
    const sites::ProductionProofSiteManifest& manifest,
    const scheduler::ProductionAggregationSchedule& schedule,
    const ProductionRecursiveSiteInventory& inventory,
    std::string* why)
{
    const ProductionRecursiveSiteInventory expected =
        BuildProductionRecursiveSiteInventory(
            manifest, schedule, inventory.hard_cap);
    if (expected.commitment.IsNull()) {
        return Fail(why, "invalid_manifest_schedule_or_arithmetic");
    }
    if (inventory != expected ||
        inventory.commitment !=
            CommitProductionRecursiveSiteInventory(inventory)) {
        return Fail(why, "noncanonical_or_substituted");
    }
    if (!inventory.enumerated_schedule_within_hard_cap ||
        !inventory.hard_cap_enforced_for_enumerated_schedule) {
        return Fail(why, "enumerated_schedule_over_hard_cap");
    }
    if (why != nullptr) {
        *why =
            "stage3:recursive_site_inventory:enumerated_cap_enforced_"
            "global_relation_and_rap_residual_open";
    }
    return true;
}

bool EnforceProductionRecursiveSiteHardCap(
    const sites::ProductionProofSiteManifest& manifest,
    const scheduler::ProductionAggregationSchedule& schedule,
    uint64_t hard_cap,
    ProductionRecursiveSiteInventory* inventory,
    std::string* why)
{
    const ProductionRecursiveSiteInventory built =
        BuildProductionRecursiveSiteInventory(
            manifest, schedule, hard_cap);
    if (inventory != nullptr) *inventory = built;
    return ValidateProductionRecursiveSiteInventory(
        manifest, schedule, built, why);
}

} // namespace matmul::v4::rc::recursive_site_inventory
