// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <test/shielded_ingress_runtime_report.h>

#include <hash.h>
#include <shielded/v2_bundle.h>
#include <shielded/v2_ingress.h>
#include <shielded/v2_types.h>

#include <algorithm>
#include <chrono>
#include <cstdint>
#include <functional>
#include <map>
#include <numeric>
#include <stdexcept>
#include <string>
#include <string_view>
#include <vector>

namespace btx::test::ingress {
namespace {

using shielded::BridgeBatchLeaf;
using shielded::BridgeBatchLeafKind;
using shielded::v2::MAX_BATCH_LEAVES;
using shielded::v2::MAX_BATCH_RESERVE_OUTPUTS;
using shielded::v2::MAX_INGRESS_OUTPUTS_PER_PROOF_SHARD;
using shielded::v2::MAX_PROOF_SHARDS;
using shielded::v2::V2IngressLeafInput;
using shielded::v2::V2IngressShardSchedule;

struct ScenarioInput
{
    std::vector<CAmount> spend_values;
    std::vector<CAmount> reserve_values;
    std::vector<V2IngressLeafInput> ingress_leaves;
};

uint256 DeterministicUint256(std::string_view tag, uint64_t index)
{
    HashWriter hw;
    hw << std::string{tag} << index;
    return hw.GetSHA256();
}

BridgeBatchLeaf BuildBridgeLeaf(uint64_t index)
{
    BridgeBatchLeaf leaf;
    leaf.kind = BridgeBatchLeafKind::SHIELD_CREDIT;
    leaf.wallet_id = DeterministicUint256("BTX_INGRESS_RUNTIME_WALLET", index);
    leaf.destination_id = DeterministicUint256("BTX_INGRESS_RUNTIME_DEST", index);
    leaf.amount = 100 + static_cast<CAmount>(index % 17);
    leaf.authorization_hash = DeterministicUint256("BTX_INGRESS_RUNTIME_AUTH", index);
    return leaf;
}

V2IngressLeafInput BuildIngressLeaf(uint64_t index)
{
    V2IngressLeafInput leaf;
    leaf.bridge_leaf = BuildBridgeLeaf(index);
    leaf.l2_id = DeterministicUint256("BTX_INGRESS_RUNTIME_L2", index);
    leaf.fee = 3 + static_cast<CAmount>(index % 5);
    if (!leaf.IsValid()) {
        throw std::runtime_error("constructed invalid ingress leaf");
    }
    return leaf;
}

std::vector<V2IngressLeafInput> BuildIngressLeaves(size_t leaf_count)
{
    std::vector<V2IngressLeafInput> leaves;
    leaves.reserve(leaf_count);
    for (size_t i = 0; i < leaf_count; ++i) {
        leaves.push_back(BuildIngressLeaf(i));
    }
    return leaves;
}

std::vector<CAmount> BuildReserveValues(size_t reserve_output_count)
{
    std::vector<CAmount> reserve_values;
    reserve_values.reserve(reserve_output_count);
    for (size_t i = 0; i < reserve_output_count; ++i) {
        reserve_values.push_back(250 + static_cast<CAmount>(i % 11) * 7);
    }
    return reserve_values;
}

CAmount ComputeLeafValue(const V2IngressLeafInput& leaf)
{
    return leaf.bridge_leaf.amount + leaf.fee;
}

std::vector<std::pair<size_t, size_t>> BuildShardOutputLayout(size_t reserve_output_count,
                                                              size_t leaf_count)
{
    std::vector<std::pair<size_t, size_t>> layout;
    size_t remaining_reserves = reserve_output_count;
    size_t remaining_leaves = leaf_count;

    while (remaining_leaves > 0) {
        const size_t reserve_this = std::min<size_t>(
            remaining_reserves,
            MAX_INGRESS_OUTPUTS_PER_PROOF_SHARD - 1);
        const size_t leaf_capacity = MAX_INGRESS_OUTPUTS_PER_PROOF_SHARD - reserve_this;
        const size_t leaves_this = std::min(remaining_leaves, leaf_capacity);
        if (leaves_this == 0) {
            throw std::runtime_error("unable to assign ingress leaves to shard layout");
        }
        layout.emplace_back(reserve_this, leaves_this);
        remaining_reserves -= reserve_this;
        remaining_leaves -= leaves_this;
    }

    if (remaining_reserves != 0) {
        throw std::runtime_error("reserve outputs exceed current proof-shard capacity");
    }
    return layout;
}

ScenarioInput BuildScenario(size_t reserve_output_count, size_t leaf_count)
{
    if (reserve_output_count == 0) {
        throw std::runtime_error("reserve_output_count must be greater than zero");
    }
    if (reserve_output_count > MAX_BATCH_RESERVE_OUTPUTS) {
        throw std::runtime_error("reserve_output_count exceeds MAX_BATCH_RESERVE_OUTPUTS");
    }
    if (leaf_count == 0) {
        throw std::runtime_error("leaf_count must be greater than zero");
    }
    if (leaf_count > MAX_BATCH_LEAVES) {
        throw std::runtime_error("leaf_count exceeds MAX_BATCH_LEAVES");
    }

    ScenarioInput scenario;
    scenario.reserve_values = BuildReserveValues(reserve_output_count);
    scenario.ingress_leaves = BuildIngressLeaves(leaf_count);

    const auto layout = BuildShardOutputLayout(reserve_output_count, leaf_count);
    scenario.spend_values.reserve(layout.size());

    size_t reserve_index{0};
    size_t leaf_index{0};
    for (const auto& [reserve_count, shard_leaf_count] : layout) {
        CAmount spend_value{0};
        for (size_t i = 0; i < reserve_count; ++i) {
            spend_value += scenario.reserve_values[reserve_index + i];
        }
        for (size_t i = 0; i < shard_leaf_count; ++i) {
            spend_value += ComputeLeafValue(scenario.ingress_leaves[leaf_index + i]);
        }
        scenario.spend_values.push_back(spend_value);
        reserve_index += reserve_count;
        leaf_index += shard_leaf_count;
    }

    return scenario;
}

uint64_t MeasureNanoseconds(const std::function<void()>& fn)
{
    const auto start = std::chrono::steady_clock::now();
    fn();
    const auto end = std::chrono::steady_clock::now();
    return static_cast<uint64_t>(
        std::chrono::duration_cast<std::chrono::nanoseconds>(end - start).count());
}

uint64_t Average(const std::vector<uint64_t>& values)
{
    if (values.empty()) return 0;
    const uint64_t total = std::accumulate(values.begin(), values.end(), uint64_t{0});
    return total / values.size();
}

uint64_t Median(std::vector<uint64_t> values)
{
    if (values.empty()) return 0;
    std::sort(values.begin(), values.end());
    const size_t mid = values.size() / 2;
    if ((values.size() % 2) == 1) {
        return values[mid];
    }
    return (values[mid - 1] + values[mid]) / 2;
}

UniValue BuildSummary(const std::vector<uint64_t>& values)
{
    UniValue summary(UniValue::VOBJ);
    summary.pushKV("count", static_cast<uint64_t>(values.size()));
    summary.pushKV("min_ns", values.empty() ? 0 : *std::min_element(values.begin(), values.end()));
    summary.pushKV("median_ns", Median(values));
    summary.pushKV("average_ns", Average(values));
    summary.pushKV("max_ns", values.empty() ? 0 : *std::max_element(values.begin(), values.end()));
    return summary;
}

template <typename Extractor>
UniValue BuildHistogram(const V2IngressShardSchedule& schedule, Extractor&& extractor)
{
    std::map<uint32_t, uint64_t> histogram;
    for (const auto& shard : schedule.shards) {
        ++histogram[extractor(shard)];
    }

    UniValue out(UniValue::VOBJ);
    for (const auto& [key, count] : histogram) {
        out.pushKV(std::to_string(key), count);
    }
    return out;
}

UniValue BuildScenarioJson(size_t reserve_output_count,
                           size_t leaf_count,
                           const ScenarioInput& scenario,
                           const V2IngressShardSchedule& schedule,
                           const std::vector<uint64_t>& schedule_times_ns)
{
    const uint64_t total_outputs = reserve_output_count + leaf_count;
    const uint64_t max_supported_leaves =
        reserve_output_count >= MAX_PROOF_SHARDS * MAX_INGRESS_OUTPUTS_PER_PROOF_SHARD
            ? 0
            : MAX_PROOF_SHARDS * MAX_INGRESS_OUTPUTS_PER_PROOF_SHARD - reserve_output_count;
    const bool within_bundle_limit = schedule.shards.size() <= MAX_PROOF_SHARDS;

    UniValue scenario_json(UniValue::VOBJ);
    scenario_json.pushKV("reserve_output_count", static_cast<uint64_t>(reserve_output_count));
    scenario_json.pushKV("ingress_leaf_count", static_cast<uint64_t>(leaf_count));
    scenario_json.pushKV("required_output_count", total_outputs);
    scenario_json.pushKV("spend_input_count", static_cast<uint64_t>(scenario.spend_values.size()));
    scenario_json.pushKV("shard_count", static_cast<uint64_t>(schedule.shards.size()));
    scenario_json.pushKV("within_bundle_proof_shard_limit", within_bundle_limit);
    scenario_json.pushKV("max_supported_ingress_leaves_at_this_reserve_count", max_supported_leaves);
    if (!within_bundle_limit) {
        scenario_json.pushKV("exceeds_bundle_proof_shard_limit_by",
                             static_cast<uint64_t>(schedule.shards.size() - MAX_PROOF_SHARDS));
    }
    scenario_json.pushKV("max_spend_inputs_per_shard",
                         static_cast<uint64_t>(schedule.MaxSpendInputCount()));
    scenario_json.pushKV("max_reserve_outputs_per_shard",
                         static_cast<uint64_t>(schedule.MaxReserveOutputCount()));
    scenario_json.pushKV("max_ingress_leaves_per_shard",
                         static_cast<uint64_t>(schedule.MaxIngressLeafCount()));
    scenario_json.pushKV("max_total_outputs_per_shard",
                         static_cast<uint64_t>(schedule.MaxOutputCount()));
    scenario_json.pushKV("schedule_runtime", BuildSummary(schedule_times_ns));
    scenario_json.pushKV("spend_input_histogram",
                         BuildHistogram(schedule, [](const auto& shard) { return shard.spend_count; }));
    scenario_json.pushKV("reserve_output_histogram",
                         BuildHistogram(schedule, [](const auto& shard) { return shard.reserve_output_count; }));
    scenario_json.pushKV("ingress_leaf_histogram",
                         BuildHistogram(schedule, [](const auto& shard) { return shard.leaf_count; }));
    scenario_json.pushKV("total_output_histogram",
                         BuildHistogram(schedule, [](const auto& shard) { return shard.TotalOutputCount(); }));
    return scenario_json;
}

} // namespace

UniValue BuildRuntimeReport(const RuntimeReportConfig& config)
{
    if (config.measured_iterations == 0) {
        throw std::runtime_error("measured_iterations must be non-zero");
    }
    if (config.reserve_output_count == 0) {
        throw std::runtime_error("reserve_output_count must be non-zero");
    }
    if (config.leaf_counts.empty()) {
        throw std::runtime_error("leaf_counts must be non-empty");
    }

    UniValue runtime_config(UniValue::VOBJ);
    runtime_config.pushKV("warmup_iterations", static_cast<uint64_t>(config.warmup_iterations));
    runtime_config.pushKV("measured_iterations", static_cast<uint64_t>(config.measured_iterations));
    runtime_config.pushKV("reserve_output_count", static_cast<uint64_t>(config.reserve_output_count));
    runtime_config.pushKV("duration_unit", "nanoseconds");
    runtime_config.pushKV("clock", "steady_clock");

    UniValue leaf_counts(UniValue::VARR);
    for (const size_t leaf_count : config.leaf_counts) {
        leaf_counts.push_back(static_cast<uint64_t>(leaf_count));
    }
    runtime_config.pushKV("leaf_counts", std::move(leaf_counts));

    UniValue limits(UniValue::VOBJ);
    limits.pushKV("max_bundle_ingress_leaves", static_cast<uint64_t>(MAX_BATCH_LEAVES));
    limits.pushKV("max_bundle_reserve_outputs", static_cast<uint64_t>(MAX_BATCH_RESERVE_OUTPUTS));
    limits.pushKV("max_proof_shards", static_cast<uint64_t>(MAX_PROOF_SHARDS));
    limits.pushKV("max_outputs_per_proof_shard", static_cast<uint64_t>(MAX_INGRESS_OUTPUTS_PER_PROOF_SHARD));
    limits.pushKV("max_matrict_inputs_per_proof_shard", static_cast<uint64_t>(shielded::ringct::MAX_MATRICT_INPUTS));

    UniValue scenarios(UniValue::VARR);
    for (const size_t leaf_count : config.leaf_counts) {
        const ScenarioInput scenario = BuildScenario(config.reserve_output_count, leaf_count);

        for (size_t i = 0; i < config.warmup_iterations; ++i) {
            auto warmup = shielded::v2::BuildCanonicalV2IngressShardSchedule(
                Span<const CAmount>{scenario.spend_values.data(), scenario.spend_values.size()},
                Span<const CAmount>{scenario.reserve_values.data(), scenario.reserve_values.size()},
                Span<const V2IngressLeafInput>{scenario.ingress_leaves.data(), scenario.ingress_leaves.size()});
            if (!warmup.has_value()) {
                throw std::runtime_error("ingress schedule warmup failed");
            }
        }

        std::vector<uint64_t> schedule_times_ns;
        schedule_times_ns.reserve(config.measured_iterations);
        std::optional<V2IngressShardSchedule> schedule;
        for (size_t i = 0; i < config.measured_iterations; ++i) {
            V2IngressShardSchedule measured_schedule;
            const uint64_t schedule_ns = MeasureNanoseconds([&] {
                auto candidate = shielded::v2::BuildCanonicalV2IngressShardSchedule(
                    Span<const CAmount>{scenario.spend_values.data(), scenario.spend_values.size()},
                    Span<const CAmount>{scenario.reserve_values.data(), scenario.reserve_values.size()},
                    Span<const V2IngressLeafInput>{scenario.ingress_leaves.data(), scenario.ingress_leaves.size()});
                if (!candidate.has_value()) {
                    throw std::runtime_error("failed to build canonical ingress shard schedule");
                }
                measured_schedule = std::move(*candidate);
            });
            if (!measured_schedule.IsValid(
                    scenario.spend_values.size(),
                    scenario.reserve_values.size(),
                    scenario.ingress_leaves.size())) {
                throw std::runtime_error("invalid canonical ingress shard schedule");
            }
            schedule_times_ns.push_back(schedule_ns);
            if (!schedule.has_value()) {
                schedule = std::move(measured_schedule);
            }
        }

        if (!schedule.has_value()) {
            throw std::runtime_error("missing measured ingress shard schedule");
        }
        scenarios.push_back(BuildScenarioJson(
            config.reserve_output_count,
            leaf_count,
            scenario,
            *schedule,
            schedule_times_ns));
    }

    UniValue out(UniValue::VOBJ);
    out.pushKV("format_version", 1);
    out.pushKV("report_kind", "v2_ingress_shard_schedule_runtime");
    out.pushKV("limits", std::move(limits));
    out.pushKV("runtime_config", std::move(runtime_config));
    out.pushKV("scenarios", std::move(scenarios));
    return out;
}

} // namespace btx::test::ingress
