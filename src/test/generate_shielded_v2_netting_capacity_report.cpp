// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <test/shielded_v2_netting_capacity_report.h>

#include <util/fs.h>

#include <cstdlib>
#include <exception>
#include <fstream>
#include <iostream>
#include <stdexcept>
#include <string>
#include <string_view>
#include <vector>

namespace {

using btx::test::shieldedv2netting::RuntimeReportConfig;
using btx::test::shieldedv2netting::RuntimeScenarioConfig;

size_t ParsePositiveSize(std::string_view value, std::string_view option_name, bool allow_zero)
{
    const auto parsed = std::stoull(std::string{value});
    if (!allow_zero && parsed == 0) {
        throw std::runtime_error(std::string{option_name} + " must be greater than zero");
    }
    return static_cast<size_t>(parsed);
}

CAmount ParsePositiveAmount(std::string_view value, std::string_view option_name)
{
    const auto parsed = std::stoll(std::string{value});
    if (parsed <= 0 || !MoneyRange(parsed)) {
        throw std::runtime_error(std::string{option_name} + " must be a valid positive amount");
    }
    return static_cast<CAmount>(parsed);
}

uint32_t ParsePositiveWindow(std::string_view value, std::string_view option_name)
{
    const auto parsed = std::stoul(std::string{value});
    if (parsed == 0) {
        throw std::runtime_error(std::string{option_name} + " must be greater than zero");
    }
    return static_cast<uint32_t>(parsed);
}

std::vector<RuntimeScenarioConfig> ParseScenarioList(std::string_view value)
{
    std::vector<RuntimeScenarioConfig> scenarios;
    while (!value.empty()) {
        const size_t comma = value.find(',');
        const std::string_view token = comma == std::string_view::npos ? value : value.substr(0, comma);
        const size_t separator = token.find('x');
        if (separator == std::string_view::npos || separator == 0 || separator + 1 >= token.size()) {
            throw std::runtime_error("scenario must be formatted as <domains>x<netting-percent>");
        }
        const size_t domain_count =
            ParsePositiveSize(token.substr(0, separator), "--scenarios", /*allow_zero=*/false);
        const auto percent = std::stoull(std::string{token.substr(separator + 1)});
        if (percent > 99) {
            throw std::runtime_error("scenario netting percent must not exceed 99");
        }
        scenarios.push_back(RuntimeScenarioConfig{
            domain_count,
            static_cast<uint64_t>(percent * 100),
        });
        if (comma == std::string_view::npos) {
            break;
        }
        value.remove_prefix(comma + 1);
    }
    if (scenarios.empty()) {
        throw std::runtime_error("--scenarios must be non-empty");
    }
    return scenarios;
}

RuntimeReportConfig ParseArgs(int argc, char** argv, fs::path& output_path)
{
    RuntimeReportConfig config;
    config.scenarios = {
        RuntimeScenarioConfig{2, 5000},
        RuntimeScenarioConfig{8, 8000},
        RuntimeScenarioConfig{32, 9500},
        RuntimeScenarioConfig{64, 9900},
    };

    for (int i = 1; i < argc; ++i) {
        const std::string_view arg{argv[i]};
        if (arg == "--help") {
            std::cout << "Usage: gen_shielded_v2_netting_capacity_report "
                         "[--warmup=N] [--samples=N] [--pair-gross-sats=N] "
                         "[--settlement-window=N] [--scenarios=2x50,8x80,32x95,64x99] "
                         "[--output=/path/report.json]\n";
            std::exit(0);
        }
        if (arg.starts_with("--warmup=")) {
            config.warmup_iterations =
                ParsePositiveSize(arg.substr(9), "--warmup", /*allow_zero=*/true);
            continue;
        }
        if (arg.starts_with("--samples=")) {
            config.measured_iterations =
                ParsePositiveSize(arg.substr(10), "--samples", /*allow_zero=*/false);
            continue;
        }
        if (arg.starts_with("--pair-gross-sats=")) {
            config.pair_gross_flow_sat =
                ParsePositiveAmount(arg.substr(18), "--pair-gross-sats");
            continue;
        }
        if (arg.starts_with("--settlement-window=")) {
            config.settlement_window =
                ParsePositiveWindow(arg.substr(20), "--settlement-window");
            continue;
        }
        if (arg.starts_with("--scenarios=")) {
            config.scenarios = ParseScenarioList(arg.substr(12));
            continue;
        }
        if (arg.starts_with("--output=")) {
            output_path = fs::PathFromString(std::string{arg.substr(9)});
            continue;
        }
        throw std::runtime_error("unknown argument: " + std::string{arg});
    }
    return config;
}

} // namespace

int main(int argc, char** argv)
{
    try {
        fs::path output_path;
        const RuntimeReportConfig config = ParseArgs(argc, argv, output_path);
        const std::string json = btx::test::shieldedv2netting::BuildRuntimeReport(config).write(2) + '\n';

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
        std::cerr << "gen_shielded_v2_netting_capacity_report: " << e.what() << '\n';
        return 1;
    }
}
