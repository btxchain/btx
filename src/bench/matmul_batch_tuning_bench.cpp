// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <bench/bench.h>

#include <arith_uint256.h>
#include <chainparams.h>
#include <common/args.h>
#include <pow.h>
#include <primitives/block.h>
#include <uint256.h>
#include <util/chaintype.h>

#include <chrono>
#include <cstdint>
#include <cstdlib>
#include <iomanip>
#include <iostream>
#include <optional>
#include <string>

namespace {
constexpr uint32_t MAINNET_LIVE_LIKE_NBITS{0x1f00a598U};
constexpr uint32_t NONCE_BUDGET{2048U};

class ScopedEnvVar
{
public:
    ScopedEnvVar(const char* name, const char* value) : m_name(name)
    {
        const char* current = std::getenv(name);
        if (current != nullptr) {
            m_had_original = true;
            m_original = current;
        }
#if defined(WIN32)
        _putenv_s(name, value != nullptr ? value : "");
#else
        if (value != nullptr) {
            setenv(name, value, 1);
        } else {
            unsetenv(name);
        }
#endif
    }

    ~ScopedEnvVar()
    {
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
    bool m_had_original{false};
    std::string m_original;
};

Consensus::Params BenchmarkConsensus(uint32_t n, uint32_t b, uint32_t r, uint32_t epsilon_bits)
{
    ArgsManager args;
    auto params{CreateChainParams(args, ChainType::REGTEST)->GetConsensus()};
    params.fMatMulPOW = true;
    params.nMatMulDimension = n;
    params.nMatMulTranscriptBlockSize = b;
    params.nMatMulNoiseRank = r;
    params.nMatMulPreHashEpsilonBits = epsilon_bits;
    params.powLimit = uint256{"ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"};
    return params;
}

CBlockHeader BuildTemplateHeader(uint32_t n, uint32_t nbits)
{
    CBlockHeader header{};
    header.nVersion = 1;
    header.nTime = 1'773'277'390U;
    header.nBits = nbits;
    header.nNonce = 1;
    header.nNonce64 = 1;
    header.hashPrevBlock = uint256{"0000000000000000000000000000000000000000000000000000000000000011"};
    header.hashMerkleRoot = uint256{"0000000000000000000000000000000000000000000000000000000000000022"};
    header.matmul_dim = static_cast<uint16_t>(n);
    header.seed_a = uint256{"6410ee507c58dca3d22f950385d38fdd5fba9dd2e424b2657a2410e92d23dc63"};
    header.seed_b = uint256{"7f165f0361461f69e2442a31fec8c26d2d95928cae37cb1673cd14fbba25f03c"};
    return header;
}

void RunMatMulSolveBatchThroughputBenchmark(
    benchmark::Bench& bench,
    const char* label,
    uint32_t n,
    uint32_t b,
    uint32_t r,
    uint32_t nbits,
    uint32_t epsilon_bits,
    std::optional<const char*> batch_size_override = std::nullopt)
{
    const auto params{BenchmarkConsensus(n, b, r, epsilon_bits)};
    const auto template_header{BuildTemplateHeader(n, nbits)};

    bench.epochs(1).epochIterations(1).run([&] {
        ScopedEnvVar backend_env("BTX_MATMUL_BACKEND", "metal");
        ScopedEnvVar batch_env("BTX_MATMUL_SOLVE_BATCH_SIZE",
                               batch_size_override.has_value() ? *batch_size_override : nullptr);
        CBlockHeader candidate{template_header};
        uint64_t max_tries{NONCE_BUDGET};

        ResetMatMulSolvePipelineStats();
        const auto start = std::chrono::steady_clock::now();
        const bool solved = SolveMatMul(candidate, params, max_tries);
        const auto stop = std::chrono::steady_clock::now();
        const auto stats = ProbeMatMulSolvePipelineStats();

        const uint64_t remaining_tries = max_tries;
        const uint64_t nonces_scanned = static_cast<uint64_t>(NONCE_BUDGET) - remaining_tries;
        const uint64_t sigma_passes = stats.prepared_inputs;
        const uint64_t digest_requests =
            stats.batched_digest_requests + (sigma_passes - stats.batched_nonce_attempts);
        const double elapsed_ms =
            std::chrono::duration_cast<std::chrono::duration<double, std::milli>>(stop - start).count();
        const double seconds = elapsed_ms / 1000.0;
        const double nonces_per_sec = seconds > 0.0 ? static_cast<double>(nonces_scanned) / seconds : 0.0;
        const double sigma_passes_per_sec = seconds > 0.0 ? static_cast<double>(sigma_passes) / seconds : 0.0;

        std::cout << std::fixed << std::setprecision(6)
                  << "MatMulSolveBatchThroughput[label=" << label
                  << ",n=" << n
                  << ",b=" << b
                  << ",r=" << r
                  << ",nbits=0x" << std::hex << nbits << std::dec
                  << ",epsilon_bits=" << epsilon_bits
                  << ",batch_size=" << stats.batch_size
                  << ",nonce_budget=" << NONCE_BUDGET << "] "
                  << "elapsed_ms=" << elapsed_ms
                  << " nonces_scanned=" << nonces_scanned
                  << " sigma_passes=" << sigma_passes
                  << " digest_requests=" << digest_requests
                  << " prepared_inputs=" << stats.prepared_inputs
                  << " overlapped_prepares=" << stats.overlapped_prepares
                  << " async_prepare_enabled=" << (stats.async_prepare_enabled ? 1 : 0)
                  << " batched_nonce_attempts=" << stats.batched_nonce_attempts
                  << " nonces_per_sec=" << nonces_per_sec
                  << " sigma_passes_per_sec=" << sigma_passes_per_sec;
        if (solved) {
            std::cout << " solved=1";
        }
        std::cout << '\n';
    });
}

void MatMulSolveBatchThroughputMainnetLiveLike(benchmark::Bench& bench)
{
    RunMatMulSolveBatchThroughputBenchmark(
        bench,
        "mainnet_live_like",
        /*n=*/512,
        /*b=*/16,
        /*r=*/8,
        MAINNET_LIVE_LIKE_NBITS,
        /*epsilon_bits=*/10);
}

void MatMulSolveBatchThroughputMainnetBatch1(benchmark::Bench& bench)
{
    RunMatMulSolveBatchThroughputBenchmark(
        bench,
        "mainnet_batch1",
        /*n=*/512,
        /*b=*/16,
        /*r=*/8,
        MAINNET_LIVE_LIKE_NBITS,
        /*epsilon_bits=*/10,
        "1");
}

void MatMulSolveBatchThroughputMainnetBatch2(benchmark::Bench& bench)
{
    RunMatMulSolveBatchThroughputBenchmark(
        bench,
        "mainnet_batch2",
        /*n=*/512,
        /*b=*/16,
        /*r=*/8,
        MAINNET_LIVE_LIKE_NBITS,
        /*epsilon_bits=*/10,
        "2");
}

void MatMulSolveBatchThroughputMainnetBatch4(benchmark::Bench& bench)
{
    RunMatMulSolveBatchThroughputBenchmark(
        bench,
        "mainnet_batch4",
        /*n=*/512,
        /*b=*/16,
        /*r=*/8,
        MAINNET_LIVE_LIKE_NBITS,
        /*epsilon_bits=*/10,
        "4");
}
} // namespace

BENCHMARK(MatMulSolveBatchThroughputMainnetLiveLike, benchmark::PriorityLevel::HIGH);
BENCHMARK(MatMulSolveBatchThroughputMainnetBatch1, benchmark::PriorityLevel::HIGH);
BENCHMARK(MatMulSolveBatchThroughputMainnetBatch2, benchmark::PriorityLevel::HIGH);
BENCHMARK(MatMulSolveBatchThroughputMainnetBatch4, benchmark::PriorityLevel::HIGH);
