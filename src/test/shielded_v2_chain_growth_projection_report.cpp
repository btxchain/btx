// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <test/shielded_v2_chain_growth_projection_report.h>

#include <algorithm>
#include <array>
#include <cmath>
#include <cstdint>
#include <limits>
#include <stdexcept>
#include <string_view>
#include <tuple>

namespace btx::test::shieldedv2growth {
namespace {

static constexpr uint64_t SECONDS_PER_DAY{24 * 60 * 60};
static constexpr uint64_t DAYS_PER_YEAR{365};
static constexpr uint64_t BPS_DENOMINATOR{10'000};

struct TxCountsPerDay
{
    uint64_t direct_send{0};
    uint64_t ingress_batch{0};
    uint64_t egress_batch{0};
    uint64_t rebalance{0};
    uint64_t settlement_anchor{0};
};

struct ResourceTotals
{
    long double serialized_size_bytes{0};
    long double tx_weight{0};
    long double verify_units{0};
    long double scan_units{0};
    long double tree_update_units{0};
};

struct StateGrowthTotals
{
    uint64_t commitments_per_day{0};
    uint64_t nullifiers_per_day{0};
    uint64_t retained_index_bytes_per_day{0};
    uint64_t snapshot_appendix_bytes_per_day{0};
    uint64_t nullifier_cache_bytes_per_day{0};
    uint64_t bounded_anchor_history_bytes_per_day{0};
    uint64_t retained_state_bytes_per_day{0};
};

[[nodiscard]] std::string FamilyName(RepresentativeFamily family)
{
    switch (family) {
    case RepresentativeFamily::DIRECT_SEND:
        return "direct_send";
    case RepresentativeFamily::INGRESS_BATCH:
        return "ingress_batch";
    case RepresentativeFamily::EGRESS_BATCH:
        return "egress_batch";
    case RepresentativeFamily::REBALANCE:
        return "rebalance";
    case RepresentativeFamily::SETTLEMENT_ANCHOR:
        return "settlement_anchor";
    }
    throw std::runtime_error("unknown representative family");
}

[[nodiscard]] const FamilyFootprint& RequireFamily(const RuntimeReportConfig& config, RepresentativeFamily family)
{
    const auto it = std::find_if(config.families.begin(), config.families.end(), [&](const auto& footprint) {
        return footprint.family == family;
    });
    if (it == config.families.end()) {
        throw std::runtime_error("missing representative family footprint: " + FamilyName(family));
    }
    return *it;
}

[[nodiscard]] uint64_t CeilDivUint64(uint64_t numerator, uint64_t denominator)
{
    if (denominator == 0) {
        throw std::runtime_error("attempted divide-by-zero");
    }
    return numerator == 0 ? 0 : 1 + ((numerator - 1) / denominator);
}

[[nodiscard]] uint64_t ClampToUint64(long double value)
{
    if (!(value > 0)) return 0;
    if (value >= static_cast<long double>(std::numeric_limits<uint64_t>::max())) {
        return std::numeric_limits<uint64_t>::max();
    }
    return static_cast<uint64_t>(value);
}

[[nodiscard]] uint64_t FloorToUint64(long double value)
{
    if (!(value > 0)) return 0;
    if (value >= static_cast<long double>(std::numeric_limits<uint64_t>::max())) {
        return std::numeric_limits<uint64_t>::max();
    }
    return static_cast<uint64_t>(std::floor(value));
}

[[nodiscard]] uint64_t ScaleBps(uint64_t total, uint32_t bps)
{
    return static_cast<uint64_t>(
        (static_cast<unsigned long long>(total) * static_cast<unsigned long long>(bps)) / BPS_DENOMINATOR);
}

[[nodiscard]] long double UtilizationBps(long double used, uint64_t limit_per_block, uint64_t blocks_per_day)
{
    if (!(used > 0) || limit_per_block == 0 || blocks_per_day == 0) return 0;
    const long double daily_limit =
        static_cast<long double>(limit_per_block) * static_cast<long double>(blocks_per_day);
    return (used * 10'000.0L) / daily_limit;
}

[[nodiscard]] TxCountsPerDay ComputeTxCounts(const WorkloadScenarioConfig& workload,
                                             const FamilyFootprint& direct_send,
                                             const FamilyFootprint& ingress_batch,
                                             const FamilyFootprint& egress_batch)
{
    const uint64_t direct_actions =
        ScaleBps(workload.boundary_actions_per_day, workload.direct_send_share_bps);
    const uint64_t ingress_actions =
        ScaleBps(workload.boundary_actions_per_day, workload.ingress_batch_share_bps);
    const uint64_t egress_actions = workload.boundary_actions_per_day - direct_actions - ingress_actions;

    TxCountsPerDay counts;
    counts.direct_send = CeilDivUint64(direct_actions, direct_send.logical_actions_per_tx);
    counts.ingress_batch = CeilDivUint64(ingress_actions, ingress_batch.logical_actions_per_tx);
    counts.egress_batch = CeilDivUint64(egress_actions, egress_batch.logical_actions_per_tx);
    counts.rebalance = workload.settlement_windows_per_day;
    counts.settlement_anchor = workload.settlement_windows_per_day;
    return counts;
}

[[nodiscard]] ResourceTotals ComputeResourceTotals(const TxCountsPerDay& counts,
                                                  const FamilyFootprint& direct_send,
                                                  const FamilyFootprint& ingress_batch,
                                                  const FamilyFootprint& egress_batch,
                                                  const FamilyFootprint& rebalance,
                                                  const FamilyFootprint& settlement_anchor)
{
    const auto accumulate = [](ResourceTotals& totals, uint64_t tx_count, const FamilyFootprint& footprint) {
        totals.serialized_size_bytes +=
            static_cast<long double>(tx_count) * static_cast<long double>(footprint.serialized_size_bytes);
        totals.tx_weight +=
            static_cast<long double>(tx_count) * static_cast<long double>(footprint.tx_weight);
        totals.verify_units +=
            static_cast<long double>(tx_count) * static_cast<long double>(footprint.verify_units);
        totals.scan_units +=
            static_cast<long double>(tx_count) * static_cast<long double>(footprint.scan_units);
        totals.tree_update_units +=
            static_cast<long double>(tx_count) * static_cast<long double>(footprint.tree_update_units);
    };

    ResourceTotals totals;
    accumulate(totals, counts.direct_send, direct_send);
    accumulate(totals, counts.ingress_batch, ingress_batch);
    accumulate(totals, counts.egress_batch, egress_batch);
    accumulate(totals, counts.rebalance, rebalance);
    accumulate(totals, counts.settlement_anchor, settlement_anchor);
    return totals;
}

[[nodiscard]] StateGrowthTotals ComputeStateGrowthTotals(const TxCountsPerDay& counts,
                                                         const StateRetentionConfig& state,
                                                         const FamilyFootprint& direct_send,
                                                         const FamilyFootprint& ingress_batch,
                                                         const FamilyFootprint& egress_batch,
                                                         const FamilyFootprint& rebalance)
{
    const uint64_t commitments_per_day =
        counts.direct_send * direct_send.commitments_per_tx +
        counts.ingress_batch * ingress_batch.commitments_per_tx +
        counts.egress_batch * egress_batch.commitments_per_tx +
        counts.rebalance * rebalance.commitments_per_tx;
    const uint64_t nullifiers_per_day =
        counts.direct_send * direct_send.nullifiers_per_tx +
        counts.ingress_batch * ingress_batch.nullifiers_per_tx +
        counts.egress_batch * egress_batch.nullifiers_per_tx +
        counts.rebalance * rebalance.nullifiers_per_tx;

    const uint64_t retained_commitment_index_bytes = state.retain_commitment_index
        ? commitments_per_day * (state.commitment_index_key_bytes + state.commitment_index_value_bytes)
        : 0;
    const uint64_t retained_nullifier_index_bytes = state.retain_nullifier_index
        ? nullifiers_per_day * (state.nullifier_index_key_bytes + state.nullifier_index_value_bytes)
        : 0;
    const uint64_t snapshot_commitment_bytes = state.snapshot_include_commitments
        ? commitments_per_day * state.snapshot_commitment_bytes
        : 0;
    const uint64_t snapshot_nullifier_bytes = state.snapshot_include_nullifiers
        ? nullifiers_per_day * state.snapshot_nullifier_bytes
        : 0;
    const uint64_t bounded_anchor_history_bytes =
        static_cast<uint64_t>(counts.settlement_anchor) *
        state.bounded_anchor_history_bytes_per_settlement_window;

    StateGrowthTotals totals;
    totals.commitments_per_day = commitments_per_day;
    totals.nullifiers_per_day = nullifiers_per_day;
    totals.retained_index_bytes_per_day =
        retained_commitment_index_bytes + retained_nullifier_index_bytes;
    totals.snapshot_appendix_bytes_per_day =
        snapshot_commitment_bytes + snapshot_nullifier_bytes;
    totals.nullifier_cache_bytes_per_day = nullifiers_per_day * state.nullifier_cache_bytes;
    totals.bounded_anchor_history_bytes_per_day = bounded_anchor_history_bytes;
    totals.retained_state_bytes_per_day =
        totals.retained_index_bytes_per_day +
        totals.snapshot_appendix_bytes_per_day +
        totals.bounded_anchor_history_bytes_per_day;
    return totals;
}

[[nodiscard]] UniValue BuildFamilyJson(const FamilyFootprint& footprint,
                                       const std::vector<BlockLimitConfig>& block_limits)
{
    UniValue out(UniValue::VOBJ);
    out.pushKV("family", FamilyName(footprint.family));
    out.pushKV("serialized_size_bytes", footprint.serialized_size_bytes);
    out.pushKV("tx_weight", footprint.tx_weight);
    out.pushKV("verify_units", footprint.verify_units);
    out.pushKV("scan_units", footprint.scan_units);
    out.pushKV("tree_update_units", footprint.tree_update_units);
    out.pushKV("logical_actions_per_tx", footprint.logical_actions_per_tx);
    out.pushKV("commitments_per_tx", footprint.commitments_per_tx);
    out.pushKV("nullifiers_per_tx", footprint.nullifiers_per_tx);

    UniValue capacities(UniValue::VARR);
    for (const auto& limit : block_limits) {
        std::vector<std::pair<std::string, uint64_t>> dimension_caps;
        if (footprint.serialized_size_bytes > 0) {
            dimension_caps.emplace_back(
                "serialized_size",
                limit.block_serialized_limit_bytes / footprint.serialized_size_bytes);
        }
        if (footprint.tx_weight > 0) {
            dimension_caps.emplace_back(
                "weight",
                limit.block_weight_limit / footprint.tx_weight);
        }
        if (footprint.verify_units > 0) {
            dimension_caps.emplace_back(
                "shielded_verify_units",
                limit.block_verify_limit / footprint.verify_units);
        }
        if (footprint.scan_units > 0) {
            dimension_caps.emplace_back(
                "shielded_scan_units",
                limit.block_scan_limit / footprint.scan_units);
        }
        if (footprint.tree_update_units > 0) {
            dimension_caps.emplace_back(
                "shielded_tree_update_units",
                limit.block_tree_update_limit / footprint.tree_update_units);
        }

        const auto best = std::min_element(dimension_caps.begin(), dimension_caps.end(), [](const auto& lhs, const auto& rhs) {
            return lhs.second < rhs.second;
        });

        UniValue capacity(UniValue::VOBJ);
        capacity.pushKV("block_limit", limit.label);
        capacity.pushKV("binding_limit", best->first);
        capacity.pushKV("max_transactions_per_block", best->second);
        capacity.pushKV("max_actions_per_block",
                        best->second * footprint.logical_actions_per_tx);
        capacities.push_back(std::move(capacity));
    }
    out.pushKV("capacity_by_block_limit", std::move(capacities));
    return out;
}

} // namespace

UniValue BuildRuntimeReport(const RuntimeReportConfig& config)
{
    if (config.block_interval_seconds == 0) {
        throw std::runtime_error("block_interval_seconds must be positive");
    }
    if (config.families.size() != 5) {
        throw std::runtime_error("families must provide exactly five representative footprints");
    }
    if (config.block_limits.empty()) {
        throw std::runtime_error("at least one block limit scenario is required");
    }
    if (config.workloads.empty()) {
        throw std::runtime_error("at least one workload scenario is required");
    }

    const auto& direct_send = RequireFamily(config, RepresentativeFamily::DIRECT_SEND);
    const auto& ingress_batch = RequireFamily(config, RepresentativeFamily::INGRESS_BATCH);
    const auto& egress_batch = RequireFamily(config, RepresentativeFamily::EGRESS_BATCH);
    const auto& rebalance = RequireFamily(config, RepresentativeFamily::REBALANCE);
    const auto& settlement_anchor = RequireFamily(config, RepresentativeFamily::SETTLEMENT_ANCHOR);

    if (direct_send.logical_actions_per_tx == 0 ||
        ingress_batch.logical_actions_per_tx == 0 ||
        egress_batch.logical_actions_per_tx == 0) {
        throw std::runtime_error("boundary families must carry at least one logical action per transaction");
    }

    for (const auto& workload : config.workloads) {
        if (workload.boundary_actions_per_day == 0) {
            throw std::runtime_error("boundary_actions_per_day must be positive");
        }
        if (workload.direct_send_share_bps + workload.ingress_batch_share_bps +
                workload.egress_batch_share_bps !=
            BPS_DENOMINATOR) {
            throw std::runtime_error("workload boundary shares must sum to 10,000 bps");
        }
    }
    for (const auto& limit : config.block_limits) {
        if (limit.label.empty()) {
            throw std::runtime_error("block limit labels must be non-empty");
        }
        if (limit.block_serialized_limit_bytes == 0 || limit.block_weight_limit == 0 ||
            limit.block_verify_limit == 0 || limit.block_scan_limit == 0 ||
            limit.block_tree_update_limit == 0) {
            throw std::runtime_error("block limit scenario must set all limits");
        }
    }

    const uint64_t blocks_per_day = SECONDS_PER_DAY / config.block_interval_seconds;
    const uint64_t blocks_per_year = blocks_per_day * DAYS_PER_YEAR;

    UniValue report(UniValue::VOBJ);
    report.pushKV("format_version", 1);
    report.pushKV("report_kind", "v2_chain_growth_projection");

    UniValue cadence(UniValue::VOBJ);
    cadence.pushKV("block_interval_seconds", config.block_interval_seconds);
    cadence.pushKV("blocks_per_day", blocks_per_day);
    cadence.pushKV("blocks_per_year", blocks_per_year);
    report.pushKV("cadence", std::move(cadence));

    UniValue retention(UniValue::VOBJ);
    retention.pushKV("retain_commitment_index", config.state_retention.retain_commitment_index);
    retention.pushKV("retain_nullifier_index", config.state_retention.retain_nullifier_index);
    retention.pushKV("snapshot_include_commitments", config.state_retention.snapshot_include_commitments);
    retention.pushKV("snapshot_include_nullifiers", config.state_retention.snapshot_include_nullifiers);
    retention.pushKV("commitment_index_entry_bytes",
                     config.state_retention.commitment_index_key_bytes +
                         config.state_retention.commitment_index_value_bytes);
    retention.pushKV("nullifier_index_entry_bytes",
                     config.state_retention.nullifier_index_key_bytes +
                         config.state_retention.nullifier_index_value_bytes);
    retention.pushKV("snapshot_commitment_bytes",
                     config.state_retention.snapshot_commitment_bytes);
    retention.pushKV("snapshot_nullifier_bytes",
                     config.state_retention.snapshot_nullifier_bytes);
    retention.pushKV("nullifier_cache_bytes",
                     config.state_retention.nullifier_cache_bytes);
    retention.pushKV("bounded_anchor_history_bytes_per_settlement_window",
                     config.state_retention.bounded_anchor_history_bytes_per_settlement_window);
    retention.pushKV("snapshot_target_bytes", config.state_retention.snapshot_target_bytes);
    report.pushKV("state_retention", std::move(retention));

    UniValue family_json(UniValue::VARR);
    for (const auto& footprint : config.families) {
        family_json.push_back(BuildFamilyJson(footprint, config.block_limits));
    }
    report.pushKV("representative_families", std::move(family_json));

    UniValue workloads(UniValue::VARR);
    for (const auto& workload : config.workloads) {
        const TxCountsPerDay tx_counts =
            ComputeTxCounts(workload, direct_send, ingress_batch, egress_batch);
        const ResourceTotals resources =
            ComputeResourceTotals(tx_counts, direct_send, ingress_batch, egress_batch, rebalance, settlement_anchor);
        const StateGrowthTotals state =
            ComputeStateGrowthTotals(tx_counts,
                                     config.state_retention,
                                     direct_send,
                                     ingress_batch,
                                     egress_batch,
                                     rebalance);

        UniValue workload_json(UniValue::VOBJ);
        workload_json.pushKV("label", workload.label);
        workload_json.pushKV("boundary_actions_per_day", workload.boundary_actions_per_day);
        workload_json.pushKV("boundary_actions_per_block_at_cadence",
                             blocks_per_day > 0 ? workload.boundary_actions_per_day / blocks_per_day : 0);
        workload_json.pushKV("settlement_windows_per_day",
                             static_cast<uint64_t>(workload.settlement_windows_per_day));

        UniValue shares(UniValue::VOBJ);
        shares.pushKV("direct_send_share_bps", workload.direct_send_share_bps);
        shares.pushKV("ingress_batch_share_bps", workload.ingress_batch_share_bps);
        shares.pushKV("egress_batch_share_bps", workload.egress_batch_share_bps);
        workload_json.pushKV("boundary_mix", std::move(shares));

        UniValue tx_counts_json(UniValue::VOBJ);
        tx_counts_json.pushKV("direct_send", tx_counts.direct_send);
        tx_counts_json.pushKV("ingress_batch", tx_counts.ingress_batch);
        tx_counts_json.pushKV("egress_batch", tx_counts.egress_batch);
        tx_counts_json.pushKV("rebalance", tx_counts.rebalance);
        tx_counts_json.pushKV("settlement_anchor", tx_counts.settlement_anchor);
        workload_json.pushKV("tx_counts_per_day", std::move(tx_counts_json));

        UniValue state_json(UniValue::VOBJ);
        state_json.pushKV("commitments_per_day", state.commitments_per_day);
        state_json.pushKV("nullifiers_per_day", state.nullifiers_per_day);
        state_json.pushKV("retained_index_bytes_per_day", state.retained_index_bytes_per_day);
        state_json.pushKV("snapshot_appendix_bytes_per_day", state.snapshot_appendix_bytes_per_day);
        state_json.pushKV("nullifier_cache_bytes_per_day", state.nullifier_cache_bytes_per_day);
        state_json.pushKV("bounded_anchor_history_bytes_per_day", state.bounded_anchor_history_bytes_per_day);
        state_json.pushKV("retained_state_bytes_per_day", state.retained_state_bytes_per_day);
        state_json.pushKV("retained_state_bytes_per_year",
                          state.retained_state_bytes_per_day * DAYS_PER_YEAR);
        state_json.pushKV("snapshot_appendix_bytes_per_year",
                          state.snapshot_appendix_bytes_per_day * DAYS_PER_YEAR);
        state_json.pushKV("snapshot_target_days",
                          state.snapshot_appendix_bytes_per_day > 0
                              ? CeilDivUint64(config.state_retention.snapshot_target_bytes,
                                              state.snapshot_appendix_bytes_per_day)
                              : 0);
        workload_json.pushKV("state_growth", std::move(state_json));

        UniValue projections(UniValue::VARR);
        for (const auto& limit : config.block_limits) {
            const uint64_t required_blocks_by_serialized =
                CeilDivUint64(ClampToUint64(resources.serialized_size_bytes), limit.block_serialized_limit_bytes);
            const uint64_t required_blocks_by_weight =
                CeilDivUint64(ClampToUint64(resources.tx_weight), limit.block_weight_limit);
            const uint64_t required_blocks_by_verify =
                CeilDivUint64(ClampToUint64(resources.verify_units), limit.block_verify_limit);
            const uint64_t required_blocks_by_scan =
                CeilDivUint64(ClampToUint64(resources.scan_units), limit.block_scan_limit);
            const uint64_t required_blocks_by_tree =
                CeilDivUint64(ClampToUint64(resources.tree_update_units), limit.block_tree_update_limit);

            const uint64_t required_blocks_per_day = std::max({
                required_blocks_by_serialized,
                required_blocks_by_weight,
                required_blocks_by_verify,
                required_blocks_by_scan,
                required_blocks_by_tree,
            });

            const ResourceTotals fixed_resources = ComputeResourceTotals(
                TxCountsPerDay{0, 0, 0, tx_counts.rebalance, tx_counts.settlement_anchor},
                direct_send,
                ingress_batch,
                egress_batch,
                rebalance,
                settlement_anchor);
            const ResourceTotals variable_resources = ComputeResourceTotals(
                TxCountsPerDay{tx_counts.direct_send, tx_counts.ingress_batch, tx_counts.egress_batch, 0, 0},
                direct_send,
                ingress_batch,
                egress_batch,
                rebalance,
                settlement_anchor);

            const auto actions_cap = [&](long double fixed_daily, long double variable_daily, uint64_t block_limit) -> uint64_t {
                const long double capacity_daily =
                    static_cast<long double>(block_limit) * static_cast<long double>(blocks_per_day);
                if (fixed_daily >= capacity_daily) return 0;
                if (!(variable_daily > 0)) return std::numeric_limits<uint64_t>::max();
                const long double scale = capacity_daily - fixed_daily;
                return FloorToUint64(
                    static_cast<long double>(workload.boundary_actions_per_day) * scale / variable_daily);
            };

            const uint64_t max_actions_by_serialized =
                actions_cap(fixed_resources.serialized_size_bytes, variable_resources.serialized_size_bytes,
                            limit.block_serialized_limit_bytes);
            const uint64_t max_actions_by_weight =
                actions_cap(fixed_resources.tx_weight, variable_resources.tx_weight,
                            limit.block_weight_limit);
            const uint64_t max_actions_by_verify =
                actions_cap(fixed_resources.verify_units, variable_resources.verify_units,
                            limit.block_verify_limit);
            const uint64_t max_actions_by_scan =
                actions_cap(fixed_resources.scan_units, variable_resources.scan_units,
                            limit.block_scan_limit);
            const uint64_t max_actions_by_tree =
                actions_cap(fixed_resources.tree_update_units, variable_resources.tree_update_units,
                            limit.block_tree_update_limit);

            const auto action_caps = std::array<std::pair<std::string_view, uint64_t>, 5>{{
                {"serialized_size", max_actions_by_serialized},
                {"weight", max_actions_by_weight},
                {"shielded_verify_units", max_actions_by_verify},
                {"shielded_scan_units", max_actions_by_scan},
                {"shielded_tree_update_units", max_actions_by_tree},
            }};
            const auto action_best = std::min_element(action_caps.begin(), action_caps.end(), [](const auto& lhs, const auto& rhs) {
                return lhs.second < rhs.second;
            });

            UniValue projection(UniValue::VOBJ);
            projection.pushKV("block_limit", limit.label);
            projection.pushKV("chain_bytes_per_day", ClampToUint64(resources.serialized_size_bytes));
            projection.pushKV("chain_bytes_per_year",
                              ClampToUint64(resources.serialized_size_bytes) * DAYS_PER_YEAR);

            UniValue required(UniValue::VOBJ);
            required.pushKV("serialized_size", required_blocks_by_serialized);
            required.pushKV("weight", required_blocks_by_weight);
            required.pushKV("shielded_verify_units", required_blocks_by_verify);
            required.pushKV("shielded_scan_units", required_blocks_by_scan);
            required.pushKV("shielded_tree_update_units", required_blocks_by_tree);
            required.pushKV("max", required_blocks_per_day);
            projection.pushKV("required_blocks_per_day", std::move(required));

            UniValue utilization(UniValue::VOBJ);
            utilization.pushKV("serialized_size_bps",
                               ClampToUint64(UtilizationBps(resources.serialized_size_bytes,
                                                           limit.block_serialized_limit_bytes,
                                                           blocks_per_day)));
            utilization.pushKV("weight_bps",
                               ClampToUint64(UtilizationBps(resources.tx_weight,
                                                           limit.block_weight_limit,
                                                           blocks_per_day)));
            utilization.pushKV("shielded_verify_units_bps",
                               ClampToUint64(UtilizationBps(resources.verify_units,
                                                           limit.block_verify_limit,
                                                           blocks_per_day)));
            utilization.pushKV("shielded_scan_units_bps",
                               ClampToUint64(UtilizationBps(resources.scan_units,
                                                           limit.block_scan_limit,
                                                           blocks_per_day)));
            utilization.pushKV("shielded_tree_update_units_bps",
                               ClampToUint64(UtilizationBps(resources.tree_update_units,
                                                           limit.block_tree_update_limit,
                                                           blocks_per_day)));
            projection.pushKV("average_block_utilization", std::move(utilization));

            projection.pushKV("feasible_at_cadence", required_blocks_per_day <= blocks_per_day);
            projection.pushKV("spare_blocks_per_day",
                              required_blocks_per_day <= blocks_per_day
                                  ? blocks_per_day - required_blocks_per_day
                                  : 0);

            UniValue max_actions(UniValue::VOBJ);
            max_actions.pushKV("binding_limit", std::string{action_best->first});
            max_actions.pushKV("serialized_size", max_actions_by_serialized);
            max_actions.pushKV("weight", max_actions_by_weight);
            max_actions.pushKV("shielded_verify_units", max_actions_by_verify);
            max_actions.pushKV("shielded_scan_units", max_actions_by_scan);
            max_actions.pushKV("shielded_tree_update_units", max_actions_by_tree);
            max_actions.pushKV("max_boundary_actions_per_day_at_cadence", action_best->second);
            max_actions.pushKV("max_boundary_actions_per_year_at_cadence",
                               action_best->second * DAYS_PER_YEAR);
            projection.pushKV("capacity_at_cadence", std::move(max_actions));

            projections.push_back(std::move(projection));
        }

        workload_json.pushKV("block_limit_projections", std::move(projections));
        workloads.push_back(std::move(workload_json));
    }

    report.pushKV("workloads", std::move(workloads));
    return report;
}

} // namespace btx::test::shieldedv2growth
