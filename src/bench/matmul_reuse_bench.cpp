// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <bench/bench.h>

#include <matmul/matmul_pow.h>
#include <matmul/noise.h>
#include <matmul/transcript.h>
#include <primitives/block.h>

#include <algorithm>
#include <chrono>
#include <cstdint>
#include <iomanip>
#include <iostream>
#include <numeric>
#include <vector>

namespace {
constexpr uint32_t SAMPLE_COUNT{6};

struct AttemptStats {
    double mean_ms;
    double median_ms;
};

CBlockHeader BuildTemplateHeader(uint32_t n)
{
    CBlockHeader header{};
    header.nVersion = 1;
    header.nTime = 1'738'800'000;
    header.nBits = 0x2100ffffU;
    header.nNonce = 1;
    header.nNonce64 = 1;
    header.hashPrevBlock = uint256{"0000000000000000000000000000000000000000000000000000000000000001"};
    header.hashMerkleRoot = uint256{"0000000000000000000000000000000000000000000000000000000000000002"};
    header.matmul_dim = static_cast<uint16_t>(n);
    header.seed_a = uint256{"0000000000000000000000000000000000000000000000000000000000000011"};
    header.seed_b = uint256{"0000000000000000000000000000000000000000000000000000000000000022"};
    return header;
}

AttemptStats Summarize(std::vector<double> samples_ms)
{
    std::sort(samples_ms.begin(), samples_ms.end());
    const double mean_ms = std::accumulate(samples_ms.begin(), samples_ms.end(), 0.0) / samples_ms.size();
    const double median_ms = 0.5 * (samples_ms[(samples_ms.size() / 2) - 1] + samples_ms[samples_ms.size() / 2]);
    return AttemptStats{mean_ms, median_ms};
}

void RunReuseBenchmark(benchmark::Bench& bench, uint32_t n, uint32_t b, uint32_t r)
{
    const CBlockHeader template_header = BuildTemplateHeader(n);
    const matmul::Matrix a = matmul::FromSeed(template_header.seed_a, n);
    const matmul::Matrix b_matrix = matmul::FromSeed(template_header.seed_b, n);
    const auto clean_block_products = matmul::transcript::PrecomputeCleanBlockProducts(a, b_matrix, b);

    bench.epochs(1).epochIterations(1).run([&] {
        std::vector<double> baseline_samples_ms;
        std::vector<double> replay_samples_ms;
        baseline_samples_ms.reserve(SAMPLE_COUNT);
        replay_samples_ms.reserve(SAMPLE_COUNT);

        for (uint32_t i = 0; i < SAMPLE_COUNT; ++i) {
            CBlockHeader candidate{template_header};
            candidate.nNonce64 = static_cast<uint64_t>(template_header.nNonce64) + i;
            candidate.nNonce = static_cast<uint32_t>(candidate.nNonce64);

            const uint256 sigma = matmul::DeriveSigma(candidate);
            const auto noise = matmul::noise::Generate(sigma, n, r);
            const matmul::Matrix a_prime = a + (noise.E_L * noise.E_R);
            const matmul::Matrix b_prime = b_matrix + (noise.F_L * noise.F_R);

            {
                const auto start = std::chrono::steady_clock::now();
                (void)matmul::transcript::CanonicalMatMul(a_prime, b_prime, b, sigma).transcript_hash;
                const auto stop = std::chrono::steady_clock::now();
                baseline_samples_ms.push_back(
                    std::chrono::duration_cast<std::chrono::duration<double, std::milli>>(stop - start).count());
            }

            {
                const auto start = std::chrono::steady_clock::now();
                (void)matmul::transcript::ReplayCanonicalHashWithReusableCleanProducts(
                    a,
                    b_matrix,
                    clean_block_products,
                    noise,
                    b,
                    sigma);
                const auto stop = std::chrono::steady_clock::now();
                replay_samples_ms.push_back(
                    std::chrono::duration_cast<std::chrono::duration<double, std::milli>>(stop - start).count());
            }
        }

        const AttemptStats baseline = Summarize(std::move(baseline_samples_ms));
        const AttemptStats replay = Summarize(std::move(replay_samples_ms));
        const double speedup = replay.mean_ms > 0.0 ? baseline.mean_ms / replay.mean_ms : 0.0;

        std::cout << std::fixed << std::setprecision(6)
                  << "MatMulReuseReplay[n=" << n << ",b=" << b << ",r=" << r << "] "
                  << "samples=" << SAMPLE_COUNT
                  << " baseline_mean_ms=" << baseline.mean_ms
                  << " baseline_median_ms=" << baseline.median_ms
                  << " replay_mean_ms=" << replay.mean_ms
                  << " replay_median_ms=" << replay.median_ms
                  << " replay_speedup=" << speedup
                  << '\n';
    });
}

void MatMulReuseReplayMainnet(benchmark::Bench& bench)
{
    RunReuseBenchmark(bench, /*n=*/512, /*b=*/16, /*r=*/8);
}

void MatMulReuseReplayTestnet(benchmark::Bench& bench)
{
    RunReuseBenchmark(bench, /*n=*/256, /*b=*/8, /*r=*/4);
}
} // namespace

BENCHMARK(MatMulReuseReplayMainnet, benchmark::PriorityLevel::HIGH);
BENCHMARK(MatMulReuseReplayTestnet, benchmark::PriorityLevel::HIGH);
