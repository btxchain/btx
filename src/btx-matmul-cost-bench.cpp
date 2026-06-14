// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <arith_uint256.h>
#include <chainparams.h>
#include <common/args.h>
#include <matmul/matmul_pow.h>
#include <matmul/matrix.h>
#include <matmul/noise.h>
#include <matmul/transcript.h>
#include <pow.h>
#include <primitives/block.h>
#include <uint256.h>
#include <util/chaintype.h>
#include <util/translation.h>

#include <univalue.h>

#include <algorithm>
#include <chrono>
#include <cstdint>
#include <exception>
#include <iostream>
#include <limits>
#include <numeric>
#include <optional>
#include <stdexcept>
#include <string>
#include <string_view>
#include <vector>

const TranslateFn G_TRANSLATION_FUN{nullptr};

namespace {

struct Options {
    uint32_t iterations{3};
    uint32_t n{512};
    uint32_t b{16};
    uint32_t r{8};
    uint32_t nbits{0x1e063c74U};
    uint32_t epsilon_bits{18};
    uint32_t seed_version{3};
    int32_t block_height{130'500};
    int64_t parent_mtp{1'780'000'000};
};

struct Timings {
    double seed_derivation_us{0.0};
    double matrix_generation_us{0.0};
    double sigma_us{0.0};
    double noise_generation_us{0.0};
    double perturbation_us{0.0};
    double product_digest_us{0.0};
    double accepted_candidate_total_us{0.0};
};

std::optional<uint64_t> ParseUintArg(std::string_view text)
{
    try {
        size_t consumed{0};
        std::string value_text{text};
        int base{10};
        if (value_text.size() > 2 &&
            value_text[0] == '0' &&
            (value_text[1] == 'x' || value_text[1] == 'X')) {
            base = 16;
        }
        const uint64_t value = std::stoull(value_text, &consumed, base);
        if (consumed != text.size()) return std::nullopt;
        return value;
    } catch (const std::exception&) {
        return std::nullopt;
    }
}

bool ParseInt64Arg(std::string_view text, int64_t& out)
{
    try {
        size_t consumed{0};
        const long long parsed = std::stoll(std::string{text}, &consumed, 10);
        if (consumed != text.size()) return false;
        out = parsed;
        return true;
    } catch (const std::exception&) {
        return false;
    }
}

uint256 ParseUint256(std::string_view hex)
{
    const auto parsed = uint256::FromHex(hex);
    if (!parsed.has_value()) {
        throw std::runtime_error("invalid uint256 literal in matmul cost benchmark");
    }
    return *parsed;
}

void PrintUsage(std::ostream& out)
{
    out << "Usage: btx-matmul-cost-bench"
        << " [--iterations <count>] [--n <dim>] [--b <block>] [--r <rank>]"
        << " [--nbits <compact>] [--epsilon-bits <count>]"
        << " [--seed-version <2|3>] [--block-height <height>] [--parent-mtp <time>]"
        << std::endl;
}

bool ParseArgs(int argc, char* argv[], Options& options)
{
    auto parse_uint32 = [&](std::string_view arg_name, std::string_view value, uint32_t& out) -> bool {
        const auto parsed = ParseUintArg(value);
        if (!parsed.has_value() || *parsed == 0 || *parsed > std::numeric_limits<uint32_t>::max()) {
            std::cerr << "error: invalid value for " << arg_name << ": " << value << std::endl;
            return false;
        }
        out = static_cast<uint32_t>(*parsed);
        return true;
    };
    auto parse_uint32_allow_zero = [&](std::string_view arg_name, std::string_view value, uint32_t& out) -> bool {
        const auto parsed = ParseUintArg(value);
        if (!parsed.has_value() || *parsed > std::numeric_limits<uint32_t>::max()) {
            std::cerr << "error: invalid value for " << arg_name << ": " << value << std::endl;
            return false;
        }
        out = static_cast<uint32_t>(*parsed);
        return true;
    };

    auto parse_int32 = [&](std::string_view arg_name, std::string_view value, int32_t& out) -> bool {
        int64_t parsed{0};
        if (!ParseInt64Arg(value, parsed) ||
            parsed < std::numeric_limits<int32_t>::min() ||
            parsed > std::numeric_limits<int32_t>::max()) {
            std::cerr << "error: invalid value for " << arg_name << ": " << value << std::endl;
            return false;
        }
        out = static_cast<int32_t>(parsed);
        return true;
    };

    for (int i = 1; i < argc; ++i) {
        const std::string arg{argv[i]};
        if (arg == "--help" || arg == "-h") {
            PrintUsage(std::cout);
            return false;
        }

        auto parse_kv = [&](std::string_view name, auto&& setter) -> bool {
            const std::string prefix = std::string{name} + "=";
            if (arg.rfind(prefix, 0) == 0) {
                return setter(std::string_view{arg}.substr(prefix.size()));
            }
            if (arg == name) {
                if (i + 1 >= argc) {
                    std::cerr << "error: " << name << " requires a value" << std::endl;
                    return false;
                }
                return setter(argv[++i]);
            }
            return true;
        };

        bool consumed = false;
        if (arg == "--iterations" || arg.rfind("--iterations=", 0) == 0) {
            consumed = true;
            if (!parse_kv("--iterations", [&](std::string_view value) { return parse_uint32("--iterations", value, options.iterations); })) return false;
        } else if (arg == "--n" || arg.rfind("--n=", 0) == 0) {
            consumed = true;
            if (!parse_kv("--n", [&](std::string_view value) { return parse_uint32("--n", value, options.n); })) return false;
        } else if (arg == "--b" || arg.rfind("--b=", 0) == 0) {
            consumed = true;
            if (!parse_kv("--b", [&](std::string_view value) { return parse_uint32("--b", value, options.b); })) return false;
        } else if (arg == "--r" || arg.rfind("--r=", 0) == 0) {
            consumed = true;
            if (!parse_kv("--r", [&](std::string_view value) { return parse_uint32("--r", value, options.r); })) return false;
        } else if (arg == "--nbits" || arg.rfind("--nbits=", 0) == 0) {
            consumed = true;
            if (!parse_kv("--nbits", [&](std::string_view value) { return parse_uint32("--nbits", value, options.nbits); })) return false;
        } else if (arg == "--epsilon-bits" || arg.rfind("--epsilon-bits=", 0) == 0) {
            consumed = true;
            if (!parse_kv("--epsilon-bits", [&](std::string_view value) { return parse_uint32_allow_zero("--epsilon-bits", value, options.epsilon_bits); })) return false;
        } else if (arg == "--seed-version" || arg.rfind("--seed-version=", 0) == 0) {
            consumed = true;
            if (!parse_kv("--seed-version", [&](std::string_view value) {
                    if (!parse_uint32("--seed-version", value, options.seed_version)) return false;
                    if (options.seed_version != 2 && options.seed_version != 3) {
                        std::cerr << "error: --seed-version must be 2 or 3" << std::endl;
                        return false;
                    }
                    return true;
                })) return false;
        } else if (arg == "--block-height" || arg.rfind("--block-height=", 0) == 0) {
            consumed = true;
            if (!parse_kv("--block-height", [&](std::string_view value) { return parse_int32("--block-height", value, options.block_height); })) return false;
        } else if (arg == "--parent-mtp" || arg.rfind("--parent-mtp=", 0) == 0) {
            consumed = true;
            if (!parse_kv("--parent-mtp", [&](std::string_view value) {
                    if (!ParseInt64Arg(value, options.parent_mtp)) {
                        std::cerr << "error: invalid value for --parent-mtp: " << value << std::endl;
                        return false;
                    }
                    return true;
                })) return false;
        }

        if (!consumed) {
            std::cerr << "error: unknown argument: " << arg << std::endl;
            PrintUsage(std::cerr);
            return false;
        }
    }
    return true;
}

CBlockHeader BuildCandidateHeader(uint32_t n, uint32_t nbits, uint64_t nonce64)
{
    CBlockHeader candidate{};
    candidate.nVersion = 4;
    candidate.hashPrevBlock = ParseUint256("0000000000000000000000000000000000000000000000000000000000000011");
    candidate.hashMerkleRoot = ParseUint256("0000000000000000000000000000000000000000000000000000000000000022");
    candidate.nTime = 1'773'277'390U;
    candidate.nBits = nbits;
    candidate.nNonce64 = nonce64;
    candidate.nNonce = static_cast<uint32_t>(nonce64);
    candidate.matmul_dim = static_cast<uint16_t>(n);
    candidate.matmul_digest.SetNull();
    return candidate;
}

template <typename F>
double TimeUs(F&& func)
{
    const auto start = std::chrono::steady_clock::now();
    func();
    const auto stop = std::chrono::steady_clock::now();
    return std::chrono::duration<double, std::micro>(stop - start).count();
}

double Mean(const std::vector<double>& values)
{
    if (values.empty()) return 0.0;
    return std::accumulate(values.begin(), values.end(), 0.0) / static_cast<double>(values.size());
}

double Median(std::vector<double> values)
{
    if (values.empty()) return 0.0;
    std::sort(values.begin(), values.end());
    const size_t mid = values.size() / 2;
    if ((values.size() & 1U) == 0U) return (values[mid - 1] + values[mid]) / 2.0;
    return values[mid];
}

UniValue SummarizeSeries(const std::vector<double>& values)
{
    UniValue out(UniValue::VOBJ);
    out.pushKV("count", static_cast<uint64_t>(values.size()));
    if (values.empty()) {
        out.pushKV("mean_us", 0.0);
        out.pushKV("median_us", 0.0);
        out.pushKV("min_us", 0.0);
        out.pushKV("max_us", 0.0);
        return out;
    }

    const auto [min_it, max_it] = std::minmax_element(values.begin(), values.end());
    out.pushKV("mean_us", Mean(values));
    out.pushKV("median_us", Median(values));
    out.pushKV("min_us", *min_it);
    out.pushKV("max_us", *max_it);
    return out;
}

void AppendTiming(std::vector<double>& values, double value)
{
    values.push_back(value);
}

arith_uint256 SaturatingLeftShiftLocal(const arith_uint256& value, uint32_t shift)
{
    if (shift == 0 || value == 0) return value;
    if (shift >= 256) return ~arith_uint256{0};
    arith_uint256 mask = ~arith_uint256{0};
    mask >>= shift;
    if (value > mask) return ~arith_uint256{0};
    return value << shift;
}

} // namespace

int main(int argc, char* argv[])
{
    for (int i = 1; i < argc; ++i) {
        const std::string arg{argv[i]};
        if (arg == "--help" || arg == "-h") {
            PrintUsage(std::cout);
            return 0;
        }
    }

    Options options;
    if (!ParseArgs(argc, argv, options)) return argc > 1 ? 1 : 0;
    if (options.n == 0 || options.b == 0 || options.r == 0 ||
        options.n % options.b != 0 || options.r > options.n ||
        options.n > std::numeric_limits<uint16_t>::max()) {
        std::cerr << "error: invalid MatMul dimensions" << std::endl;
        return 1;
    }

    std::vector<double> seed_derivation;
    std::vector<double> matrix_generation;
    std::vector<double> sigma;
    std::vector<double> noise_generation;
    std::vector<double> perturbation;
    std::vector<double> product_digest;
    std::vector<double> accepted_total;
    seed_derivation.reserve(options.iterations);
    matrix_generation.reserve(options.iterations);
    sigma.reserve(options.iterations);
    noise_generation.reserve(options.iterations);
    perturbation.reserve(options.iterations);
    product_digest.reserve(options.iterations);
    accepted_total.reserve(options.iterations);

    std::vector<uint256> digest_sink;
    digest_sink.reserve(options.iterations);

    for (uint32_t i = 0; i < options.iterations; ++i) {
        Timings timings;
        CBlockHeader candidate = BuildCandidateHeader(options.n, options.nbits, i + 1);

        const auto candidate_start = std::chrono::steady_clock::now();
        timings.seed_derivation_us = TimeUs([&] {
            if (options.seed_version == 3) {
                candidate.seed_a = DeterministicMatMulSeedV3(candidate, static_cast<uint32_t>(options.block_height), options.parent_mtp, 0);
                candidate.seed_b = DeterministicMatMulSeedV3(candidate, static_cast<uint32_t>(options.block_height), options.parent_mtp, 1);
            } else {
                candidate.seed_a = DeterministicMatMulSeedV2(candidate, static_cast<uint32_t>(options.block_height), 0);
                candidate.seed_b = DeterministicMatMulSeedV2(candidate, static_cast<uint32_t>(options.block_height), 1);
            }
        });

        matmul::Matrix a(1, 1);
        matmul::Matrix b_matrix(1, 1);
        timings.matrix_generation_us = TimeUs([&] {
            a = matmul::FromSeed(candidate.seed_a, options.n);
            b_matrix = matmul::FromSeed(candidate.seed_b, options.n);
        });

        uint256 candidate_sigma;
        timings.sigma_us = TimeUs([&] {
            candidate_sigma = matmul::DeriveSigma(candidate);
        });

        std::optional<matmul::noise::NoisePair> noise;
        timings.noise_generation_us = TimeUs([&] {
            noise = matmul::noise::Generate(candidate_sigma, options.n, options.r);
        });

        matmul::Matrix a_prime(1, 1);
        matmul::Matrix b_prime(1, 1);
        timings.perturbation_us = TimeUs([&] {
            const matmul::Matrix e = noise->E_L * noise->E_R;
            const matmul::Matrix f = noise->F_L * noise->F_R;
            a_prime = a + e;
            b_prime = b_matrix + f;
        });

        uint256 digest;
        timings.product_digest_us = TimeUs([&] {
            digest = matmul::transcript::ComputeProductCommittedDigestFromPerturbed(
                a_prime,
                b_prime,
                options.b,
                candidate_sigma);
        });
        const auto candidate_stop = std::chrono::steady_clock::now();
        timings.accepted_candidate_total_us =
            std::chrono::duration<double, std::micro>(candidate_stop - candidate_start).count();
        digest_sink.push_back(digest);

        AppendTiming(seed_derivation, timings.seed_derivation_us);
        AppendTiming(matrix_generation, timings.matrix_generation_us);
        AppendTiming(sigma, timings.sigma_us);
        AppendTiming(noise_generation, timings.noise_generation_us);
        AppendTiming(perturbation, timings.perturbation_us);
        AppendTiming(product_digest, timings.product_digest_us);
        AppendTiming(accepted_total, timings.accepted_candidate_total_us);
    }

    const double mean_total = Mean(accepted_total);
    const double mean_matrix = Mean(matrix_generation);
    const double mean_digest = Mean(product_digest);
    const double mean_noise = Mean(noise_generation);
    const double mean_perturbation = Mean(perturbation);
    const double mean_seed = Mean(seed_derivation);
    const double mean_sigma = Mean(sigma);

    double pre_hash_pass_probability = 1.0;
    if (options.epsilon_bits > 0) {
        if (const auto target = DeriveTarget(options.nbits, uint256{"ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"})) {
            constexpr double kTwoToMinus256 = 8.6361685550944446253863518628003995711160003644363e-78;
            const arith_uint256 sigma_target = SaturatingLeftShiftLocal(*target, options.epsilon_bits);
            pre_hash_pass_probability = std::min(1.0, sigma_target.getdouble() * kTwoToMinus256);
        }
    }
    const double gate_hash_us = mean_seed + mean_sigma;
    const double expensive_candidate_us = mean_matrix + mean_noise + mean_perturbation + mean_digest;
    const double amortized_per_scanned_nonce_us = gate_hash_us + pre_hash_pass_probability * expensive_candidate_us;

    UniValue output(UniValue::VOBJ);
    UniValue options_obj(UniValue::VOBJ);
    options_obj.pushKV("iterations", options.iterations);
    options_obj.pushKV("n", options.n);
    options_obj.pushKV("b", options.b);
    options_obj.pushKV("r", options.r);
    options_obj.pushKV("nbits", options.nbits);
    options_obj.pushKV("epsilon_bits", options.epsilon_bits);
    options_obj.pushKV("seed_version", options.seed_version);
    options_obj.pushKV("block_height", options.block_height);
    options_obj.pushKV("parent_mtp", options.parent_mtp);
    output.pushKV("options", std::move(options_obj));

    UniValue timings_obj(UniValue::VOBJ);
    timings_obj.pushKV("seed_derivation", SummarizeSeries(seed_derivation));
    timings_obj.pushKV("matrix_generation_ab", SummarizeSeries(matrix_generation));
    timings_obj.pushKV("sigma", SummarizeSeries(sigma));
    timings_obj.pushKV("noise_generation", SummarizeSeries(noise_generation));
    timings_obj.pushKV("perturbation", SummarizeSeries(perturbation));
    timings_obj.pushKV("product_digest_dense", SummarizeSeries(product_digest));
    timings_obj.pushKV("accepted_candidate_total", SummarizeSeries(accepted_total));
    output.pushKV("timings", std::move(timings_obj));

    UniValue ratios(UniValue::VOBJ);
    ratios.pushKV("matrix_generation_share_of_accepted_total", mean_total > 0.0 ? mean_matrix / mean_total : 0.0);
    ratios.pushKV("product_digest_share_of_accepted_total", mean_total > 0.0 ? mean_digest / mean_total : 0.0);
    ratios.pushKV("noise_generation_share_of_accepted_total", mean_total > 0.0 ? mean_noise / mean_total : 0.0);
    ratios.pushKV("perturbation_share_of_accepted_total", mean_total > 0.0 ? mean_perturbation / mean_total : 0.0);
    ratios.pushKV("matrix_generation_vs_product_digest", mean_digest > 0.0 ? mean_matrix / mean_digest : 0.0);
    output.pushKV("ratios", std::move(ratios));

    UniValue amortized(UniValue::VOBJ);
    amortized.pushKV("pre_hash_gate_enabled", options.epsilon_bits > 0);
    amortized.pushKV("pre_hash_gate_pass_probability_estimate", pre_hash_pass_probability);
    amortized.pushKV("gate_hash_us_per_scanned_nonce", gate_hash_us);
    amortized.pushKV("expensive_candidate_us_on_gate_pass", expensive_candidate_us);
    amortized.pushKV("amortized_us_per_scanned_nonce", amortized_per_scanned_nonce_us);
    amortized.pushKV("gate_hash_share", amortized_per_scanned_nonce_us > 0.0 ? gate_hash_us / amortized_per_scanned_nonce_us : 0.0);
    amortized.pushKV("matrix_generation_share", amortized_per_scanned_nonce_us > 0.0 ? (pre_hash_pass_probability * mean_matrix) / amortized_per_scanned_nonce_us : 0.0);
    amortized.pushKV("product_digest_share", amortized_per_scanned_nonce_us > 0.0 ? (pre_hash_pass_probability * mean_digest) / amortized_per_scanned_nonce_us : 0.0);
    amortized.pushKV("noise_generation_share", amortized_per_scanned_nonce_us > 0.0 ? (pre_hash_pass_probability * mean_noise) / amortized_per_scanned_nonce_us : 0.0);
    amortized.pushKV("perturbation_share", amortized_per_scanned_nonce_us > 0.0 ? (pre_hash_pass_probability * mean_perturbation) / amortized_per_scanned_nonce_us : 0.0);
    output.pushKV("amortized_per_scanned_nonce", std::move(amortized));

    UniValue estimates(UniValue::VOBJ);
    estimates.pushKV("ab_matrix_oracle_calls", static_cast<uint64_t>(2) * options.n * options.n);
    estimates.pushKV("noise_matrix_oracle_calls", static_cast<uint64_t>(4) * options.n * options.r);
    estimates.pushKV("compression_vector_oracle_calls", static_cast<uint64_t>(options.b) * options.b);
    estimates.pushKV("dense_product_field_muladds", static_cast<uint64_t>(options.n) * options.n * options.n);
    estimates.pushKV("noise_low_rank_field_muladds", static_cast<uint64_t>(2) * options.n * options.n * options.r);
    estimates.pushKV("pre_hash_gate_pass_probability_estimate", pre_hash_pass_probability);
    if (options.epsilon_bits > 0) {
        estimates.pushKV("expected_sigma_passes_per_digest_hit_from_epsilon", static_cast<uint64_t>(1) << std::min<uint32_t>(options.epsilon_bits, 63));
    }
    output.pushKV("operation_estimates", std::move(estimates));

    output.pushKV("digest_sink", digest_sink.empty() ? "" : digest_sink.back().GetHex());
    std::cout << output.write(2) << std::endl;
    return 0;
}
