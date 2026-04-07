// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <chainparams.h>
#include <test/util/smile2_proof_redesign_harness.h>

#include <util/fs.h>
#include <util/chaintype.h>

#include <cstdlib>
#include <exception>
#include <fstream>
#include <iostream>
#include <stdexcept>
#include <string>
#include <string_view>

namespace {

size_t ParsePositiveSize(std::string_view value, std::string_view option_name, bool allow_zero)
{
    const auto parsed = std::stoull(std::string{value});
    if (!allow_zero && parsed == 0) {
        throw std::runtime_error(std::string{option_name} + " must be greater than zero");
    }
    return static_cast<size_t>(parsed);
}

btx::test::smile2redesign::ProofRedesignFrameworkConfig ParseArgs(int argc,
                                                                  char** argv,
                                                                  fs::path& output_path)
{
    using btx::test::smile2redesign::MakeFastProofRedesignFrameworkConfig;
    using btx::test::smile2redesign::MakeLaunchBaselineProofRedesignFrameworkConfig;

    auto config = MakeLaunchBaselineProofRedesignFrameworkConfig();
    for (int i = 1; i < argc; ++i) {
        const std::string_view arg{argv[i]};
        if (arg == "--help") {
            std::cout << "Usage: gen_smile2_proof_redesign_report "
                         "[--profile=fast|baseline] [--warmup=N] [--samples=N] "
                         "[--output=/path/report.json]\n";
            std::exit(0);
        }
        if (arg.starts_with("--profile=")) {
            const std::string_view profile = arg.substr(10);
            if (profile == "fast") {
                config = MakeFastProofRedesignFrameworkConfig();
            } else if (profile == "baseline") {
                config = MakeLaunchBaselineProofRedesignFrameworkConfig();
            } else {
                throw std::runtime_error("unsupported profile: " + std::string{profile});
            }
            continue;
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
        SelectParams(ChainType::REGTEST);
        fs::path output_path;
        const auto config = ParseArgs(argc, argv, output_path);
        const std::string json =
            btx::test::smile2redesign::BuildProofRedesignFrameworkReport(config).write(2) + '\n';

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
        std::cerr << "gen_smile2_proof_redesign_report: " << e.what() << '\n';
        return 1;
    }
}
