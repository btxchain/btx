// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <test/shielded_ingress_runtime_report.h>

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

using btx::test::ingress::RuntimeReportConfig;

size_t ParsePositiveSize(std::string_view value, std::string_view option_name, bool allow_zero)
{
    const auto parsed = std::stoull(std::string{value});
    if (!allow_zero && parsed == 0) {
        throw std::runtime_error(std::string{option_name} + " must be greater than zero");
    }
    return static_cast<size_t>(parsed);
}

std::vector<size_t> ParseLeafCounts(std::string_view value)
{
    std::vector<size_t> counts;
    size_t begin{0};
    while (begin < value.size()) {
        const size_t end = value.find(',', begin);
        const std::string_view token = value.substr(begin, end == std::string_view::npos ? value.size() - begin
                                                                                         : end - begin);
        counts.push_back(ParsePositiveSize(token, "--leaf-counts", /*allow_zero=*/false));
        if (end == std::string_view::npos) break;
        begin = end + 1;
    }
    if (counts.empty()) {
        throw std::runtime_error("--leaf-counts must be non-empty");
    }
    return counts;
}

RuntimeReportConfig ParseArgs(int argc, char** argv, fs::path& output_path)
{
    RuntimeReportConfig config;
    for (int i = 1; i < argc; ++i) {
        const std::string_view arg{argv[i]};
        if (arg == "--help") {
            std::cout << "Usage: gen_shielded_ingress_runtime_report "
                         "[--warmup=N] [--samples=N] [--reserve-outputs=N] "
                         "[--leaf-counts=100,1000,5000,10000] [--output=/path/report.json]\n";
            std::exit(0);
        }
        if (arg.starts_with("--warmup=")) {
            config.warmup_iterations = ParsePositiveSize(arg.substr(9), "--warmup", /*allow_zero=*/true);
            continue;
        }
        if (arg.starts_with("--samples=")) {
            config.measured_iterations = ParsePositiveSize(arg.substr(10), "--samples", /*allow_zero=*/false);
            continue;
        }
        if (arg.starts_with("--reserve-outputs=")) {
            config.reserve_output_count = ParsePositiveSize(arg.substr(18), "--reserve-outputs", /*allow_zero=*/false);
            continue;
        }
        if (arg.starts_with("--leaf-counts=")) {
            config.leaf_counts = ParseLeafCounts(arg.substr(14));
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
        const std::string json = btx::test::ingress::BuildRuntimeReport(config).write(2) + '\n';

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
        std::cerr << "gen_shielded_ingress_runtime_report: " << e.what() << '\n';
        return 1;
    }
}
