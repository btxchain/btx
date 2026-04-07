// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <test/shielded_ingress_proof_runtime_report.h>
#include <test/shielded_v2_chain_growth_projection_report.h>
#include <test/shielded_v2_egress_runtime_report.h>
#include <test/shielded_v2_netting_capacity_report.h>
#include <test/shielded_v2_send_runtime_report.h>

#include <chainparams.h>
#include <consensus/consensus.h>
#include <consensus/params.h>
#include <util/fs.h>
#include <util/chaintype.h>

#include <cstdlib>
#include <exception>
#include <fstream>
#include <iostream>
#include <stdexcept>
#include <string>
#include <string_view>
#include <vector>

namespace {

using btx::test::shieldedv2growth::BlockLimitConfig;
using btx::test::shieldedv2growth::FamilyFootprint;
using btx::test::shieldedv2growth::RepresentativeFamily;
using btx::test::shieldedv2growth::RuntimeReportConfig;
using btx::test::shieldedv2growth::WorkloadScenarioConfig;

[[nodiscard]] size_t ParsePositiveSize(std::string_view value, std::string_view option_name, bool allow_zero)
{
    const auto parsed = std::stoull(std::string{value});
    if (!allow_zero && parsed == 0) {
        throw std::runtime_error(std::string{option_name} + " must be greater than zero");
    }
    return static_cast<size_t>(parsed);
}

[[nodiscard]] uint64_t ParsePositiveUint64(std::string_view value, std::string_view option_name)
{
    const auto parsed = std::stoull(std::string{value});
    if (parsed == 0) {
        throw std::runtime_error(std::string{option_name} + " must be greater than zero");
    }
    return static_cast<uint64_t>(parsed);
}

[[nodiscard]] std::vector<uint64_t> ParseCommaSeparatedUint64(std::string_view value,
                                                              std::string_view option_name)
{
    std::vector<uint64_t> parsed;
    while (!value.empty()) {
        const size_t comma = value.find(',');
        const std::string_view token =
            comma == std::string_view::npos ? value : value.substr(0, comma);
        parsed.push_back(ParsePositiveUint64(token, option_name));
        if (comma == std::string_view::npos) break;
        value.remove_prefix(comma + 1);
    }
    if (parsed.empty()) {
        throw std::runtime_error(std::string{option_name} + " must be non-empty");
    }
    return parsed;
}

[[nodiscard]] btx::test::ingress::ProofRuntimeBackendKind ParseIngressBackend(std::string_view value)
{
    if (value == "smile") {
        return btx::test::ingress::ProofRuntimeBackendKind::SMILE;
    }
    if (value == "matrict") {
        return btx::test::ingress::ProofRuntimeBackendKind::MATRICT_PLUS;
    }
    if (value == "receipt") {
        return btx::test::ingress::ProofRuntimeBackendKind::RECEIPT_BACKED;
    }
    throw std::runtime_error("unknown --ingress-backend, expected smile|matrict|receipt");
}

[[nodiscard]] std::vector<BlockLimitConfig> BuildScaledBlockLimits(const std::vector<uint64_t>& serialized_limits_mb)
{
    std::vector<BlockLimitConfig> limits;
    limits.reserve(serialized_limits_mb.size());
    for (const uint64_t serialized_limit_mb : serialized_limits_mb) {
        const uint64_t serialized_limit_bytes = serialized_limit_mb * 1'000'000ULL;
        const uint64_t scale = serialized_limit_bytes / MAX_BLOCK_SERIALIZED_SIZE;
        if (scale == 0) {
            throw std::runtime_error("block limit must not be below current 24 MB baseline");
        }
        limits.push_back(BlockLimitConfig{
            strprintf("%lluMB", static_cast<unsigned long long>(serialized_limit_mb)),
            serialized_limit_bytes,
            MAX_BLOCK_WEIGHT * scale,
            Consensus::DEFAULT_MAX_BLOCK_SHIELDED_VERIFY_COST * scale,
            Consensus::DEFAULT_MAX_BLOCK_SHIELDED_SCAN_UNITS * scale,
            Consensus::DEFAULT_MAX_BLOCK_SHIELDED_TREE_UPDATE_UNITS * scale,
        });
    }
    return limits;
}

[[nodiscard]] const UniValue& RequireField(const UniValue& object,
                                           std::string_view field,
                                           std::string_view context)
{
    const UniValue& value = object.find_value(std::string{field});
    if (value.isNull()) {
        throw std::runtime_error(strprintf("%s missing field '%s'",
                                           std::string{context},
                                           std::string{field}));
    }
    return value;
}

[[nodiscard]] const UniValue& RequireArrayEntry(const UniValue& array,
                                                size_t index,
                                                std::string_view context)
{
    if (!array.isArray() || array.size() <= index) {
        throw std::runtime_error(strprintf("%s missing array entry %u",
                                           std::string{context},
                                           static_cast<unsigned int>(index)));
    }
    return array[index];
}

[[nodiscard]] uint64_t RequireUint64(const UniValue& object,
                                     std::string_view field,
                                     std::string_view context)
{
    const UniValue& value = RequireField(object, field, context);
    if (!value.isNum()) {
        throw std::runtime_error(strprintf("%s.%s expected numeric value",
                                           std::string{context},
                                           std::string{field}));
    }
    return static_cast<uint64_t>(value.getInt<int64_t>());
}

void RequireBuiltStatus(const UniValue& report, std::string_view context)
{
    const UniValue& status = report.find_value("status");
    if (status.isNull()) {
        return;
    }
    if (!status.isStr()) {
        throw std::runtime_error(strprintf("%s.status expected string value",
                                           std::string{context}));
    }
    if (status.get_str() == "built_and_checked") {
        return;
    }

    std::string detail = strprintf("%s status=%s",
                                   std::string{context},
                                   status.get_str());
    const UniValue& rejection = report.find_value("rejection");
    if (!rejection.isNull()) {
        const UniValue& reason = rejection.find_value("reject_reason");
        if (!reason.isNull() && reason.isStr()) {
            detail += strprintf(" reject_reason=%s", reason.get_str());
        }
    }
    throw std::runtime_error(detail);
}

[[nodiscard]] FamilyFootprint ExtractSendFootprint(const btx::test::shieldedv2send::RuntimeReportConfig& config)
{
    const UniValue report = btx::test::shieldedv2send::BuildRuntimeReport(config);
    RequireBuiltStatus(report, "send report");
    const UniValue& scenarios = RequireField(report, "scenarios", "send report");
    const UniValue& scenario = RequireArrayEntry(scenarios, 0, "send report.scenarios");
    const UniValue& tx_shape = RequireField(scenario, "tx_shape", "send report.scenario");
    const UniValue& usage = RequireField(scenario, "resource_usage", "send report.scenario");
    return FamilyFootprint{
        RepresentativeFamily::DIRECT_SEND,
        RequireUint64(tx_shape, "serialized_size_bytes", "send report.scenario.tx_shape"),
        RequireUint64(tx_shape, "tx_weight", "send report.scenario.tx_shape"),
        RequireUint64(usage, "verify_units", "send report.scenario.resource_usage"),
        RequireUint64(usage, "scan_units", "send report.scenario.resource_usage"),
        RequireUint64(usage, "tree_update_units", "send report.scenario.resource_usage"),
        1,
        RequireUint64(scenario, "output_count", "send report.scenario"),
        RequireUint64(scenario, "spend_count", "send report.scenario"),
    };
}

[[nodiscard]] FamilyFootprint ExtractIngressFootprint(const btx::test::ingress::ProofRuntimeReportConfig& config)
{
    const UniValue report = btx::test::ingress::BuildProofRuntimeReport(config);
    RequireBuiltStatus(report, "ingress report");
    const UniValue& scenario = RequireField(report, "scenario", "ingress report");
    const UniValue& tx_shape = RequireField(scenario, "tx_shape", "ingress report.scenario");
    const UniValue& usage = RequireField(scenario, "resource_usage", "ingress report.scenario");
    return FamilyFootprint{
        RepresentativeFamily::INGRESS_BATCH,
        RequireUint64(tx_shape, "serialized_size_bytes", "ingress report.scenario.tx_shape"),
        RequireUint64(tx_shape, "tx_weight", "ingress report.scenario.tx_shape"),
        RequireUint64(usage, "verify_units", "ingress report.scenario.resource_usage"),
        RequireUint64(usage, "scan_units", "ingress report.scenario.resource_usage"),
        RequireUint64(usage, "tree_update_units", "ingress report.scenario.resource_usage"),
        RequireUint64(scenario, "ingress_leaf_count", "ingress report.scenario"),
        RequireUint64(scenario, "reserve_output_count", "ingress report.scenario"),
        RequireUint64(scenario, "spend_input_count", "ingress report.scenario"),
    };
}

[[nodiscard]] FamilyFootprint ExtractEgressFootprint(const btx::test::shieldedv2egress::RuntimeReportConfig& config)
{
    const UniValue report = btx::test::shieldedv2egress::BuildRuntimeReport(config);
    RequireBuiltStatus(report, "egress report");
    const UniValue& scenarios = RequireField(report, "scenarios", "egress report");
    const UniValue& scenario = RequireArrayEntry(scenarios, 0, "egress report.scenarios");
    const UniValue& tx_shape = RequireField(scenario, "tx_shape", "egress report.scenario");
    const UniValue& usage = RequireField(scenario, "resource_usage", "egress report.scenario");
    return FamilyFootprint{
        RepresentativeFamily::EGRESS_BATCH,
        RequireUint64(tx_shape, "serialized_size_bytes", "egress report.scenario.tx_shape"),
        RequireUint64(tx_shape, "tx_weight", "egress report.scenario.tx_shape"),
        RequireUint64(usage, "verify_units", "egress report.scenario.resource_usage"),
        RequireUint64(usage, "scan_units", "egress report.scenario.resource_usage"),
        RequireUint64(usage, "tree_update_units", "egress report.scenario.resource_usage"),
        RequireUint64(scenario, "output_count", "egress report.scenario"),
        RequireUint64(scenario, "output_count", "egress report.scenario"),
        0,
    };
}

[[nodiscard]] FamilyFootprint ExtractRebalanceFootprint(const UniValue& tx_metrics)
{
    const UniValue& usage = RequireField(tx_metrics, "shielded_resource_usage", "netting peak rebalance");
    return FamilyFootprint{
        RepresentativeFamily::REBALANCE,
        RequireUint64(tx_metrics, "serialized_size_bytes", "netting peak rebalance"),
        RequireUint64(tx_metrics, "tx_weight", "netting peak rebalance"),
        RequireUint64(usage, "verify_units", "netting peak rebalance.shielded_resource_usage"),
        RequireUint64(usage, "scan_units", "netting peak rebalance.shielded_resource_usage"),
        RequireUint64(usage, "tree_update_units", "netting peak rebalance.shielded_resource_usage"),
        0,
        RequireUint64(usage, "tree_update_units", "netting peak rebalance.shielded_resource_usage"),
        0,
    };
}

[[nodiscard]] FamilyFootprint ExtractSettlementFootprint(const UniValue& tx_metrics)
{
    const UniValue& usage = RequireField(tx_metrics, "shielded_resource_usage", "netting peak settlement");
    return FamilyFootprint{
        RepresentativeFamily::SETTLEMENT_ANCHOR,
        RequireUint64(tx_metrics, "serialized_size_bytes", "netting peak settlement"),
        RequireUint64(tx_metrics, "tx_weight", "netting peak settlement"),
        RequireUint64(usage, "verify_units", "netting peak settlement.shielded_resource_usage"),
        RequireUint64(usage, "scan_units", "netting peak settlement.shielded_resource_usage"),
        RequireUint64(usage, "tree_update_units", "netting peak settlement.shielded_resource_usage"),
        0,
        0,
        0,
    };
}

[[nodiscard]] std::pair<FamilyFootprint, FamilyFootprint> ExtractNettingFootprints(
    const btx::test::shieldedv2netting::RuntimeReportConfig& config)
{
    const UniValue report = btx::test::shieldedv2netting::BuildRuntimeReport(config);
    const UniValue& scenarios = RequireField(report, "scenarios", "netting report");
    const UniValue& scenario = RequireArrayEntry(scenarios, 0, "netting report.scenarios");
    const UniValue& peak_window = RequireField(scenario, "peak_window", "netting report.scenario");
    return {
        ExtractRebalanceFootprint(RequireField(peak_window,
                                              "representative_rebalance_tx",
                                              "netting report.scenario.peak_window")),
        ExtractSettlementFootprint(RequireField(peak_window,
                                               "representative_settlement_anchor_tx",
                                               "netting report.scenario.peak_window")),
    };
}

RuntimeReportConfig ParseArgs(int argc, char** argv, fs::path& output_path)
{
    constexpr std::string_view ARG_BLOCK_SIZES_MB{"--block-sizes-mb="};
    constexpr std::string_view ARG_INGRESS_BACKEND{"--ingress-backend="};
    constexpr std::string_view ARG_INGRESS_LEAVES{"--ingress-leaves="};
    constexpr std::string_view ARG_EGRESS_OUTPUTS{"--egress-outputs="};
    constexpr std::string_view ARG_EGRESS_OUTPUTS_PER_CHUNK{"--egress-outputs-per-chunk="};
    constexpr std::string_view ARG_NETTING_DOMAINS{"--netting-domains="};
    constexpr std::string_view ARG_NETTING_PERCENT{"--netting-percent="};
    constexpr std::string_view ARG_SETTLEMENT_WINDOWS_PER_DAY{"--settlement-windows-per-day="};
    constexpr std::string_view ARG_OUTPUT{"--output="};

    std::vector<uint64_t> block_sizes_mb{12, 24, 32};
    btx::test::ingress::ProofRuntimeBackendKind ingress_backend{
        btx::test::ingress::ProofRuntimeBackendKind::SMILE};
    size_t ingress_leaf_count{1000};
    size_t egress_output_count{32};
    size_t egress_outputs_per_chunk{32};
    size_t netting_domain_count{8};
    uint64_t netting_percent{80};
    uint32_t settlement_windows_per_day{96};

    for (int i = 1; i < argc; ++i) {
        const std::string_view arg{argv[i]};
        if (arg == "--help") {
            std::cout << "Usage: gen_shielded_v2_chain_growth_projection_report "
                         "[--block-sizes-mb=12,24,32] [--ingress-leaves=1000] "
                         "[--ingress-backend=smile] "
                         "[--egress-outputs=32] [--egress-outputs-per-chunk=32] "
                         "[--netting-domains=8] [--netting-percent=80] "
                         "[--settlement-windows-per-day=96] "
                         "[--output=/path/report.json]\n";
            std::exit(0);
        }
        if (arg.starts_with(ARG_BLOCK_SIZES_MB)) {
            block_sizes_mb = ParseCommaSeparatedUint64(arg.substr(ARG_BLOCK_SIZES_MB.size()), "--block-sizes-mb");
            continue;
        }
        if (arg.starts_with(ARG_INGRESS_BACKEND)) {
            ingress_backend = ParseIngressBackend(arg.substr(ARG_INGRESS_BACKEND.size()));
            continue;
        }
        if (arg.starts_with(ARG_INGRESS_LEAVES)) {
            ingress_leaf_count = ParsePositiveSize(arg.substr(ARG_INGRESS_LEAVES.size()), "--ingress-leaves", false);
            continue;
        }
        if (arg.starts_with(ARG_EGRESS_OUTPUTS)) {
            egress_output_count = ParsePositiveSize(arg.substr(ARG_EGRESS_OUTPUTS.size()), "--egress-outputs", false);
            continue;
        }
        if (arg.starts_with(ARG_EGRESS_OUTPUTS_PER_CHUNK)) {
            egress_outputs_per_chunk =
                ParsePositiveSize(arg.substr(ARG_EGRESS_OUTPUTS_PER_CHUNK.size()), "--egress-outputs-per-chunk", false);
            continue;
        }
        if (arg.starts_with(ARG_NETTING_DOMAINS)) {
            netting_domain_count = ParsePositiveSize(arg.substr(ARG_NETTING_DOMAINS.size()), "--netting-domains", false);
            continue;
        }
        if (arg.starts_with(ARG_NETTING_PERCENT)) {
            netting_percent = ParsePositiveUint64(arg.substr(ARG_NETTING_PERCENT.size()), "--netting-percent");
            if (netting_percent > 99) {
                throw std::runtime_error("--netting-percent must not exceed 99");
            }
            continue;
        }
        if (arg.starts_with(ARG_SETTLEMENT_WINDOWS_PER_DAY)) {
            settlement_windows_per_day =
                static_cast<uint32_t>(ParsePositiveUint64(arg.substr(ARG_SETTLEMENT_WINDOWS_PER_DAY.size()),
                                                          "--settlement-windows-per-day"));
            continue;
        }
        if (arg.starts_with(ARG_OUTPUT)) {
            output_path = fs::PathFromString(std::string{arg.substr(ARG_OUTPUT.size())});
            continue;
        }
        throw std::runtime_error("unknown argument: " + std::string{arg});
    }

    RuntimeReportConfig config;
    config.block_interval_seconds = 90;
    config.block_limits = BuildScaledBlockLimits(block_sizes_mb);
    config.workloads = {
        WorkloadScenarioConfig{"1b_year_1pct_boundary", 27'400, 2'000, 5'000, 3'000, settlement_windows_per_day},
        WorkloadScenarioConfig{"5b_year_1pct_boundary", 136'986, 2'000, 5'000, 3'000, settlement_windows_per_day},
        WorkloadScenarioConfig{"10b_year_1pct_boundary", 273'973, 2'000, 5'000, 3'000, settlement_windows_per_day},
    };

    config.families.push_back(ExtractSendFootprint({
        .warmup_iterations = 0,
        .measured_iterations = 1,
        .fee_sat = 1000,
        .scenarios = {btx::test::shieldedv2send::RuntimeScenarioConfig{1, 2}},
    }));
    config.families.push_back(ExtractIngressFootprint({
        .backend_kind = ingress_backend,
        .warmup_iterations = 0,
        .measured_iterations = 1,
        .reserve_output_count = 1,
        .leaf_count = ingress_leaf_count,
    }));
    config.families.push_back(ExtractEgressFootprint({
        .warmup_iterations = 0,
        .measured_iterations = 1,
        .scenarios = {btx::test::shieldedv2egress::RuntimeScenarioConfig{
            egress_output_count,
            egress_outputs_per_chunk,
        }},
    }));
    const auto [rebalance, settlement_anchor] = ExtractNettingFootprints({
        .warmup_iterations = 0,
        .measured_iterations = 1,
        .pair_gross_flow_sat = COIN,
        .settlement_window = 144,
        .scenarios = {btx::test::shieldedv2netting::RuntimeScenarioConfig{
            netting_domain_count,
            netting_percent * 100,
        }},
    });
    config.families.push_back(rebalance);
    config.families.push_back(settlement_anchor);
    return config;
}

} // namespace

int main(int argc, char** argv)
{
    try {
        SelectParams(ChainType::REGTEST);
        fs::path output_path;
        const RuntimeReportConfig config = ParseArgs(argc, argv, output_path);
        const std::string json = btx::test::shieldedv2growth::BuildRuntimeReport(config).write(2) + '\n';

        if (output_path.empty()) {
            std::cout << json;
        } else {
            std::ofstream output{output_path};
            if (!output.is_open()) {
                throw std::runtime_error("unable to open output path");
            }
            output << json;
        }
        return 0;
    } catch (const std::exception& e) {
        std::cerr << "gen_shielded_v2_chain_growth_projection_report: " << e.what() << '\n';
        return 1;
    }
}
