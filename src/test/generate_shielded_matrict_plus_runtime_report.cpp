// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <test/shielded_matrict_runtime_report.h>

#include <util/fs.h>

#include <cstdlib>
#include <exception>
#include <fstream>
#include <iostream>
#include <stdexcept>
#include <string>
#include <string_view>

namespace {

using btx::test::matrictplus::RuntimeReportConfig;

size_t ParsePositiveSize(std::string_view value, std::string_view option_name, bool allow_zero)
{
    const auto parsed = std::stoull(std::string{value});
    if (!allow_zero && parsed == 0) {
        throw std::runtime_error(std::string{option_name} + " must be greater than zero");
    }
    return static_cast<size_t>(parsed);
}

RuntimeReportConfig ParseArgs(int argc, char** argv, fs::path& output_path)
{
    RuntimeReportConfig config;
    for (int i = 1; i < argc; ++i) {
        const std::string_view arg{argv[i]};
        if (arg == "--help") {
            std::cout << "Usage: gen_shielded_matrict_plus_runtime_report [--warmup=N] [--samples=N] [--output=/path/report.json]\n";
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
        const std::string json = btx::test::matrictplus::BuildRuntimeReport(config).write(2) + '\n';

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
        std::cerr << "gen_shielded_matrict_plus_runtime_report: " << e.what() << '\n';
        return 1;
    }
}
