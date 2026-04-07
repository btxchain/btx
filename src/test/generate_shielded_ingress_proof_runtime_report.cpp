// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <chainparams.h>
#include <test/shielded_ingress_proof_runtime_report.h>

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

using btx::test::ingress::ProofRuntimeReportConfig;
using btx::test::ingress::ProofCapacitySweepConfig;
using btx::test::ingress::ProofBackendDecisionReportConfig;
using btx::test::ingress::ProofRuntimeBackendKind;

struct ParsedArgs
{
    ProofRuntimeReportConfig runtime_config;
    std::vector<size_t> leaf_counts;
    std::vector<size_t> target_leaf_counts;
};

ProofRuntimeBackendKind ParseBackend(std::string_view value)
{
    if (value == "smile") {
        return ProofRuntimeBackendKind::SMILE;
    }
    if (value == "matrict" || value == "matrict_plus") {
        return ProofRuntimeBackendKind::MATRICT_PLUS;
    }
    if (value == "receipt" || value == "receipt_backed") {
        return ProofRuntimeBackendKind::RECEIPT_BACKED;
    }
    throw std::runtime_error("unsupported backend: " + std::string{value});
}

size_t ParsePositiveSize(std::string_view value, std::string_view option_name, bool allow_zero)
{
    const auto parsed = std::stoull(std::string{value});
    if (!allow_zero && parsed == 0) {
        throw std::runtime_error(std::string{option_name} + " must be greater than zero");
    }
    return static_cast<size_t>(parsed);
}

std::vector<size_t> ParsePositiveSizeList(std::string_view value, std::string_view option_name)
{
    std::vector<size_t> out;
    while (!value.empty()) {
        const size_t comma = value.find(',');
        const std::string_view token = comma == std::string_view::npos ? value : value.substr(0, comma);
        if (token.empty()) {
            throw std::runtime_error(std::string{option_name} + " contains an empty value");
        }
        out.push_back(ParsePositiveSize(token, option_name, /*allow_zero=*/false));
        if (comma == std::string_view::npos) {
            break;
        }
        value.remove_prefix(comma + 1);
    }
    return out;
}

ParsedArgs ParseArgs(int argc, char** argv, fs::path& output_path)
{
    ParsedArgs parsed;
    bool saw_leaf_count{false};
    for (int i = 1; i < argc; ++i) {
        const std::string_view arg{argv[i]};
        if (arg == "--help") {
            std::cout << "Usage: gen_shielded_ingress_proof_runtime_report "
                         "[--backend=smile|matrict|receipt] "
                         "[--warmup=N] [--samples=N] [--reserve-outputs=N] "
                         "[--leaf-count=N | --leaf-counts=N[,M...]] "
                         "[--target-leaf-counts=N[,M...]] "
                         "[--output=/path/report.json]\n";
            std::exit(0);
        }
        if (arg.starts_with("--backend=")) {
            parsed.runtime_config.backend_kind = ParseBackend(arg.substr(10));
            continue;
        }
        if (arg.starts_with("--warmup=")) {
            parsed.runtime_config.warmup_iterations = ParsePositiveSize(arg.substr(9), "--warmup", /*allow_zero=*/true);
            continue;
        }
        if (arg.starts_with("--samples=")) {
            parsed.runtime_config.measured_iterations = ParsePositiveSize(arg.substr(10), "--samples", /*allow_zero=*/false);
            continue;
        }
        if (arg.starts_with("--reserve-outputs=")) {
            parsed.runtime_config.reserve_output_count = ParsePositiveSize(arg.substr(18), "--reserve-outputs", /*allow_zero=*/false);
            continue;
        }
        if (arg.starts_with("--leaf-count=")) {
            if (!parsed.leaf_counts.empty()) {
                throw std::runtime_error("--leaf-count cannot be combined with --leaf-counts");
            }
            parsed.runtime_config.leaf_count = ParsePositiveSize(arg.substr(13), "--leaf-count", /*allow_zero=*/false);
            saw_leaf_count = true;
            continue;
        }
        if (arg.starts_with("--leaf-counts=")) {
            if (saw_leaf_count) {
                throw std::runtime_error("--leaf-counts cannot be combined with --leaf-count");
            }
            parsed.leaf_counts = ParsePositiveSizeList(arg.substr(14), "--leaf-counts");
            continue;
        }
        if (arg.starts_with("--target-leaf-counts=")) {
            parsed.target_leaf_counts = ParsePositiveSizeList(arg.substr(21), "--target-leaf-counts");
            continue;
        }
        if (arg.starts_with("--output=")) {
            output_path = fs::PathFromString(std::string{arg.substr(9)});
            continue;
        }
        throw std::runtime_error("unknown argument: " + std::string{arg});
    }
    return parsed;
}

} // namespace

int main(int argc, char** argv)
{
    try {
        SelectParams(ChainType::REGTEST);
        fs::path output_path;
        const ParsedArgs args = ParseArgs(argc, argv, output_path);
        UniValue report;
        if (!args.target_leaf_counts.empty()) {
            if (args.leaf_counts.empty()) {
                throw std::runtime_error("--target-leaf-counts requires --leaf-counts");
            }
            report = btx::test::ingress::BuildProofBackendDecisionReport(ProofBackendDecisionReportConfig{
                .backend_kind = args.runtime_config.backend_kind,
                .warmup_iterations = args.runtime_config.warmup_iterations,
                .measured_iterations = args.runtime_config.measured_iterations,
                .reserve_output_count = args.runtime_config.reserve_output_count,
                .measured_leaf_counts = args.leaf_counts,
                .target_leaf_counts = args.target_leaf_counts,
            });
        } else if (args.leaf_counts.empty()) {
            report = btx::test::ingress::BuildProofRuntimeReport(args.runtime_config);
        } else {
            report = btx::test::ingress::BuildProofCapacitySweepReport(ProofCapacitySweepConfig{
                .backend_kind = args.runtime_config.backend_kind,
                .warmup_iterations = args.runtime_config.warmup_iterations,
                .measured_iterations = args.runtime_config.measured_iterations,
                .reserve_output_count = args.runtime_config.reserve_output_count,
                .leaf_counts = args.leaf_counts,
            });
        }
        const std::string json = report.write(2) + '\n';

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
        std::cerr << "gen_shielded_ingress_proof_runtime_report: " << e.what() << '\n';
        return 1;
    }
}
