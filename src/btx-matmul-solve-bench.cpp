// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <arith_uint256.h>
#include <chainparams.h>
#include <common/args.h>
#include <metal/matmul_accel.h>
#include <pow.h>
#include <primitives/block.h>
#include <uint256.h>
#include <util/chaintype.h>

#include <univalue.h>

#include <algorithm>
#include <chrono>
#include <cstdint>
#include <cstdlib>
#include <exception>
#include <iostream>
#include <limits>
#include <numeric>
#include <optional>
#include <stdexcept>
#include <string>
#include <string_view>
#include <thread>
#include <vector>

namespace {
constexpr uint32_t MAINNET_LIVE_LIKE_NBITS{0x1f00a598U};

struct Options {
    uint32_t iterations{8};
    uint64_t max_tries{2048};
    uint32_t n{512};
    uint32_t b{16};
    uint32_t r{8};
    uint32_t nbits{MAINNET_LIVE_LIKE_NBITS};
    uint32_t epsilon_bits{10};
    int32_t block_height{-1};
    uint32_t parallel{1};
    std::optional<std::string> backend_override;
    std::optional<std::string> async_override;
    std::optional<std::string> gpu_inputs_override;
    std::optional<std::string> batch_size_override;
    std::optional<std::string> prepare_workers_override;
    std::optional<std::string> pool_slots_override;
    std::optional<std::string> solver_threads_override;
};

std::optional<uint64_t> ParseUintArg(std::string_view text)
{
    try {
        size_t consumed{0};
        const uint64_t value = std::stoull(std::string{text}, &consumed, 10);
        if (consumed != text.size()) {
            return std::nullopt;
        }
        return value;
    } catch (const std::exception&) {
        return std::nullopt;
    }
}

uint256 ParseUint256(std::string_view hex)
{
    const auto parsed = uint256::FromHex(hex);
    if (!parsed.has_value()) {
        throw std::runtime_error("invalid uint256 literal in matmul solve benchmark");
    }
    return *parsed;
}

void PrintUsage(std::ostream& out)
{
    out << "Usage: btx-matmul-solve-bench"
        << " [--iterations <count>] [--tries <count>]"
        << " [--n <dim>] [--b <block>] [--r <rank>]"
        << " [--nbits <compact>] [--epsilon-bits <count>]"
        << " [--block-height <height>]"
        << " [--parallel <count>]"
        << " [--backend <cpu|metal|cuda|mlx>]"
        << " [--async <0|1>] [--gpu-inputs <0|1>]"
        << " [--batch-size <count>] [--prepare-workers <count>]"
        << " [--pool-slots <count>] [--solver-threads <count>]" << std::endl;
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

    auto parse_uint64 = [&](std::string_view arg_name, std::string_view value, uint64_t& out) -> bool {
        const auto parsed = ParseUintArg(value);
        if (!parsed.has_value() || *parsed == 0) {
            std::cerr << "error: invalid value for " << arg_name << ": " << value << std::endl;
            return false;
        }
        out = *parsed;
        return true;
    };

    auto parse_int32 = [&](std::string_view arg_name, std::string_view value, int32_t& out) -> bool {
        try {
            size_t consumed{0};
            const long parsed = std::stol(std::string{value}, &consumed, 10);
            if (consumed != value.size() ||
                parsed < std::numeric_limits<int32_t>::min() ||
                parsed > std::numeric_limits<int32_t>::max()) {
                std::cerr << "error: invalid value for " << arg_name << ": " << value << std::endl;
                return false;
            }
            out = static_cast<int32_t>(parsed);
            return true;
        } catch (const std::exception&) {
            std::cerr << "error: invalid value for " << arg_name << ": " << value << std::endl;
            return false;
        }
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
        } else if (arg == "--tries" || arg.rfind("--tries=", 0) == 0) {
            consumed = true;
            if (!parse_kv("--tries", [&](std::string_view value) { return parse_uint64("--tries", value, options.max_tries); })) return false;
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
            if (!parse_kv("--epsilon-bits", [&](std::string_view value) { return parse_uint32("--epsilon-bits", value, options.epsilon_bits); })) return false;
        } else if (arg == "--block-height" || arg.rfind("--block-height=", 0) == 0) {
            consumed = true;
            if (!parse_kv("--block-height", [&](std::string_view value) { return parse_int32("--block-height", value, options.block_height); })) return false;
        } else if (arg == "--parallel" || arg.rfind("--parallel=", 0) == 0) {
            consumed = true;
            if (!parse_kv("--parallel", [&](std::string_view value) { return parse_uint32("--parallel", value, options.parallel); })) return false;
        } else if (arg == "--backend" || arg.rfind("--backend=", 0) == 0) {
            consumed = true;
            if (!parse_kv("--backend", [&](std::string_view value) {
                    options.backend_override = std::string{value};
                    return true;
                })) return false;
        } else if (arg == "--async" || arg.rfind("--async=", 0) == 0) {
            consumed = true;
            if (!parse_kv("--async", [&](std::string_view value) {
                    options.async_override = std::string{value};
                    return true;
                })) return false;
        } else if (arg == "--gpu-inputs" || arg.rfind("--gpu-inputs=", 0) == 0) {
            consumed = true;
            if (!parse_kv("--gpu-inputs", [&](std::string_view value) {
                    options.gpu_inputs_override = std::string{value};
                    return true;
                })) return false;
        } else if (arg == "--batch-size" || arg.rfind("--batch-size=", 0) == 0) {
            consumed = true;
            if (!parse_kv("--batch-size", [&](std::string_view value) {
                    options.batch_size_override = std::string{value};
                    return true;
                })) return false;
        } else if (arg == "--prepare-workers" || arg.rfind("--prepare-workers=", 0) == 0) {
            consumed = true;
            if (!parse_kv("--prepare-workers", [&](std::string_view value) {
                    options.prepare_workers_override = std::string{value};
                    return true;
                })) return false;
        } else if (arg == "--pool-slots" || arg.rfind("--pool-slots=", 0) == 0) {
            consumed = true;
            if (!parse_kv("--pool-slots", [&](std::string_view value) {
                    options.pool_slots_override = std::string{value};
                    return true;
                })) return false;
        } else if (arg == "--solver-threads" || arg.rfind("--solver-threads=", 0) == 0) {
            consumed = true;
            if (!parse_kv("--solver-threads", [&](std::string_view value) {
                    options.solver_threads_override = std::string{value};
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

class ScopedEnvOverride
{
public:
    ScopedEnvOverride(const char* name, const std::optional<std::string>& value) : m_name(name)
    {
        const char* current = std::getenv(name);
        if (current != nullptr) {
            m_had_original = true;
            m_original = current;
        }
        if (!value.has_value()) {
            return;
        }
        m_applied = true;
#if defined(WIN32)
        _putenv_s(name, value->c_str());
#else
        setenv(name, value->c_str(), 1);
#endif
    }

    ~ScopedEnvOverride()
    {
        if (!m_applied) {
            return;
        }
#if defined(WIN32)
        _putenv_s(m_name, m_had_original ? m_original.c_str() : "");
#else
        if (m_had_original) {
            setenv(m_name, m_original.c_str(), 1);
        } else {
            unsetenv(m_name);
        }
#endif
    }

private:
    const char* m_name;
    bool m_applied{false};
    bool m_had_original{false};
    std::string m_original;
};

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
    if ((values.size() & 1U) == 0U) {
        return (values[mid - 1] + values[mid]) / 2.0;
    }
    return values[mid];
}

UniValue SummarizeSeries(const std::vector<double>& values)
{
    UniValue out(UniValue::VOBJ);
    out.pushKV("count", static_cast<uint64_t>(values.size()));
    if (values.empty()) {
        out.pushKV("mean", 0.0);
        out.pushKV("median", 0.0);
        out.pushKV("min", 0.0);
        out.pushKV("max", 0.0);
        return out;
    }

    const auto [min_it, max_it] = std::minmax_element(values.begin(), values.end());
    out.pushKV("mean", Mean(values));
    out.pushKV("median", Median(values));
    out.pushKV("min", *min_it);
    out.pushKV("max", *max_it);
    return out;
}

CBlockHeader BuildCandidateHeader(uint32_t n, uint32_t nbits, uint64_t nonce64)
{
    CBlockHeader candidate{};
    candidate.nVersion = 1;
    candidate.hashPrevBlock = ParseUint256("0000000000000000000000000000000000000000000000000000000000000011");
    candidate.hashMerkleRoot = ParseUint256("0000000000000000000000000000000000000000000000000000000000000022");
    candidate.nTime = 1'773'277'390U;
    candidate.nBits = nbits;
    candidate.nNonce64 = nonce64;
    candidate.nNonce = static_cast<uint32_t>(nonce64);
    candidate.matmul_dim = static_cast<uint16_t>(n);
    candidate.seed_a = ParseUint256("6410ee507c58dca3d22f950385d38fdd5fba9dd2e424b2657a2410e92d23dc63");
    candidate.seed_b = ParseUint256("7f165f0361461f69e2442a31fec8c26d2d95928cae37cb1673cd14fbba25f03c");
    candidate.matmul_digest.SetNull();
    return candidate;
}

struct IterationResult {
    double elapsed_s{0.0};
    double nonces_per_sec{0.0};
    uint64_t solved_count{0};
};

IterationResult RunSolveIteration(const Options& options, const Consensus::Params& consensus, uint32_t iteration_index)
{
    ResetMatMulSolvePipelineStats();
    ResetMatMulSolveRuntimeStats();

    IterationResult result;
    const auto start = std::chrono::steady_clock::now();
    if (options.parallel == 1) {
        CBlockHeader candidate = BuildCandidateHeader(
            options.n,
            options.nbits,
            static_cast<uint64_t>(iteration_index) * options.max_tries + 1U);
        uint64_t tries = options.max_tries;
        if (SolveMatMul(candidate, consensus, tries, options.block_height)) {
            ++result.solved_count;
        }
        result.nonces_per_sec = static_cast<double>(options.max_tries - tries);
    } else {
        std::vector<uint64_t> attempts_used(options.parallel, 0);
        std::vector<uint64_t> solved_counts(options.parallel, 0);
        std::vector<std::thread> workers;
        workers.reserve(options.parallel);

        for (uint32_t worker_index = 0; worker_index < options.parallel; ++worker_index) {
            workers.emplace_back([&, worker_index] {
                const uint64_t nonce64 =
                    ((static_cast<uint64_t>(iteration_index) * options.parallel + worker_index) * options.max_tries) + 1U;
                CBlockHeader candidate = BuildCandidateHeader(options.n, options.nbits, nonce64);
                uint64_t tries = options.max_tries;
                if (SolveMatMul(candidate, consensus, tries, options.block_height)) {
                    solved_counts[worker_index] = 1;
                }
                attempts_used[worker_index] = options.max_tries - tries;
            });
        }

        for (auto& worker : workers) {
            worker.join();
        }

        const uint64_t total_attempts = std::accumulate(attempts_used.begin(), attempts_used.end(), uint64_t{0});
        result.solved_count = std::accumulate(solved_counts.begin(), solved_counts.end(), uint64_t{0});
        result.nonces_per_sec = static_cast<double>(total_attempts);
    }
    const auto stop = std::chrono::steady_clock::now();
    result.elapsed_s = std::chrono::duration<double>(stop - start).count();
    if (result.elapsed_s > 0.0) {
        result.nonces_per_sec /= result.elapsed_s;
    } else {
        result.nonces_per_sec = 0.0;
    }
    return result;
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
    if (!ParseArgs(argc, argv, options)) {
        return argc > 1 ? 1 : 0;
    }

    ScopedEnvOverride backend_env("BTX_MATMUL_BACKEND", options.backend_override);
    ScopedEnvOverride async_env("BTX_MATMUL_PIPELINE_ASYNC", options.async_override);
    ScopedEnvOverride gpu_inputs_env("BTX_MATMUL_GPU_INPUTS", options.gpu_inputs_override);
    ScopedEnvOverride batch_size_env("BTX_MATMUL_SOLVE_BATCH_SIZE", options.batch_size_override);
    ScopedEnvOverride prepare_workers_env("BTX_MATMUL_PREPARE_WORKERS", options.prepare_workers_override);
    ScopedEnvOverride pool_slots_env("BTX_MATMUL_METAL_POOL_SLOTS", options.pool_slots_override);
    ScopedEnvOverride solver_threads_env("BTX_MATMUL_SOLVER_THREADS", options.solver_threads_override);

    ArgsManager args;
    auto consensus = CreateChainParams(args, ChainType::REGTEST)->GetConsensus();
    consensus.fMatMulPOW = true;
    consensus.nMatMulDimension = options.n;
    consensus.nMatMulTranscriptBlockSize = options.b;
    consensus.nMatMulNoiseRank = options.r;
    consensus.nMatMulPreHashEpsilonBits = options.epsilon_bits;
    consensus.powLimit = uint256{"ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"};

    std::vector<double> elapsed_s_values;
    std::vector<double> nonces_per_sec_values;
    elapsed_s_values.reserve(options.iterations);
    nonces_per_sec_values.reserve(options.iterations);

    uint64_t solved_count{0};
    MatMulSolvePipelineStats last_pipeline{};
    MatMulSolveRuntimeStats last_runtime{};

    for (uint32_t i = 0; i < options.iterations; ++i) {
        const IterationResult iteration = RunSolveIteration(options, consensus, i);
        elapsed_s_values.push_back(iteration.elapsed_s);
        nonces_per_sec_values.push_back(iteration.nonces_per_sec);
        solved_count += iteration.solved_count;
        last_pipeline = ProbeMatMulSolvePipelineStats();
        last_runtime = ProbeMatMulSolveRuntimeStats();
    }

    UniValue output(UniValue::VOBJ);
    UniValue options_obj(UniValue::VOBJ);
    options_obj.pushKV("iterations", options.iterations);
    options_obj.pushKV("max_tries", options.max_tries);
    options_obj.pushKV("n", options.n);
    options_obj.pushKV("b", options.b);
    options_obj.pushKV("r", options.r);
    options_obj.pushKV("nbits", options.nbits);
    options_obj.pushKV("epsilon_bits", options.epsilon_bits);
    options_obj.pushKV("block_height", options.block_height);
    options_obj.pushKV("parallel", options.parallel);
    options_obj.pushKV("backend_override", options.backend_override.has_value() ? UniValue(*options.backend_override) : UniValue());
    options_obj.pushKV("async_override", options.async_override.has_value() ? UniValue(*options.async_override) : UniValue());
    options_obj.pushKV("gpu_inputs_override", options.gpu_inputs_override.has_value() ? UniValue(*options.gpu_inputs_override) : UniValue());
    options_obj.pushKV("batch_size_override", options.batch_size_override.has_value() ? UniValue(*options.batch_size_override) : UniValue());
    options_obj.pushKV("prepare_workers_override", options.prepare_workers_override.has_value() ? UniValue(*options.prepare_workers_override) : UniValue());
    options_obj.pushKV("pool_slots_override", options.pool_slots_override.has_value() ? UniValue(*options.pool_slots_override) : UniValue());
    options_obj.pushKV("solver_threads_override", options.solver_threads_override.has_value() ? UniValue(*options.solver_threads_override) : UniValue());
    output.pushKV("options", std::move(options_obj));

    output.pushKV("solved_count", solved_count);
    output.pushKV("elapsed_s", SummarizeSeries(elapsed_s_values));
    output.pushKV("nonces_per_sec", SummarizeSeries(nonces_per_sec_values));

    UniValue pipeline_obj(UniValue::VOBJ);
    pipeline_obj.pushKV("parallel_solver_enabled", last_pipeline.parallel_solver_enabled);
    pipeline_obj.pushKV("parallel_solver_threads", last_pipeline.parallel_solver_threads);
    pipeline_obj.pushKV("async_prepare_enabled", last_pipeline.async_prepare_enabled);
    pipeline_obj.pushKV("cpu_confirm_candidates", last_pipeline.cpu_confirm_candidates);
    pipeline_obj.pushKV("prepared_inputs", last_pipeline.prepared_inputs);
    pipeline_obj.pushKV("overlapped_prepares", last_pipeline.overlapped_prepares);
    pipeline_obj.pushKV("prefetched_batches", last_pipeline.prefetched_batches);
    pipeline_obj.pushKV("prefetched_inputs", last_pipeline.prefetched_inputs);
    pipeline_obj.pushKV("async_prepare_submissions", last_pipeline.async_prepare_submissions);
    pipeline_obj.pushKV("async_prepare_completions", last_pipeline.async_prepare_completions);
    pipeline_obj.pushKV("async_prepare_worker_threads", last_pipeline.async_prepare_worker_threads);
    pipeline_obj.pushKV("batch_size", last_pipeline.batch_size);
    pipeline_obj.pushKV("batched_digest_requests", last_pipeline.batched_digest_requests);
    pipeline_obj.pushKV("batched_nonce_attempts", last_pipeline.batched_nonce_attempts);
    output.pushKV("last_pipeline_stats", std::move(pipeline_obj));

    UniValue runtime_obj(UniValue::VOBJ);
    runtime_obj.pushKV("attempts", last_runtime.attempts);
    runtime_obj.pushKV("solved_attempts", last_runtime.solved_attempts);
    runtime_obj.pushKV("failed_attempts", last_runtime.failed_attempts);
    runtime_obj.pushKV("total_elapsed_us", last_runtime.total_elapsed_us);
    runtime_obj.pushKV("last_elapsed_us", last_runtime.last_elapsed_us);
    runtime_obj.pushKV("max_elapsed_us", last_runtime.max_elapsed_us);
    output.pushKV("last_runtime_stats", std::move(runtime_obj));

    const auto pool_stats = btx::metal::ProbeMatMulBufferPool();
    UniValue pool_obj(UniValue::VOBJ);
    pool_obj.pushKV("available", pool_stats.available);
    pool_obj.pushKV("initialized", pool_stats.initialized);
    pool_obj.pushKV("allocation_events", pool_stats.allocation_events);
    pool_obj.pushKV("reuse_events", pool_stats.reuse_events);
    pool_obj.pushKV("wait_events", pool_stats.wait_events);
    pool_obj.pushKV("slot_count", pool_stats.slot_count);
    pool_obj.pushKV("active_slots", pool_stats.active_slots);
    pool_obj.pushKV("high_water_slots", pool_stats.high_water_slots);
    pool_obj.pushKV("inflight_submissions", pool_stats.inflight_submissions);
    pool_obj.pushKV("peak_inflight_submissions", pool_stats.peak_inflight_submissions);
    pool_obj.pushKV("completed_submissions", pool_stats.completed_submissions);
    pool_obj.pushKV("n", pool_stats.n);
    pool_obj.pushKV("b", pool_stats.b);
    pool_obj.pushKV("r", pool_stats.r);
    pool_obj.pushKV("reason", pool_stats.reason);
    output.pushKV("buffer_pool_stats", std::move(pool_obj));

    std::cout << output.write(2) << std::endl;
    return 0;
}
