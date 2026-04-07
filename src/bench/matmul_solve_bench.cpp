// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <bench/bench.h>

#include <chainparams.h>
#include <common/args.h>
#include <pow.h>
#include <primitives/block.h>
#include <uint256.h>
#include <util/chaintype.h>

#include <algorithm>
#include <chrono>
#include <cstdint>
#include <iomanip>
#include <iostream>
#include <numeric>
#include <vector>

namespace {
constexpr uint32_t SAMPLE_COUNT{100};
constexpr uint32_t EASY_NBITS{0x2100ffffU};

struct AttemptStats {
    double mean_ms;
    double median_ms;
    uint32_t successes;
};

Consensus::Params BenchmarkConsensus(uint32_t n, uint32_t b, uint32_t r)
{
    ArgsManager args;
    auto params{CreateChainParams(args, ChainType::REGTEST)->GetConsensus()};
    params.fMatMulPOW = true;
    params.nMatMulDimension = n;
    params.nMatMulTranscriptBlockSize = b;
    params.nMatMulNoiseRank = r;
    params.powLimit = uint256{"ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"};
    return params;
}

CBlockHeader BuildTemplateHeader(uint32_t n)
{
    CBlockHeader header{};
    header.nVersion = 1;
    header.nTime = 1'738'800'000;
    header.nBits = EASY_NBITS;
    header.nNonce = 1;
    header.nNonce64 = 1;
    header.hashPrevBlock = uint256{"0000000000000000000000000000000000000000000000000000000000000001"};
    header.hashMerkleRoot = uint256{"0000000000000000000000000000000000000000000000000000000000000002"};
    header.matmul_dim = static_cast<uint16_t>(n);
    header.seed_a = uint256{"0000000000000000000000000000000000000000000000000000000000000011"};
    header.seed_b = uint256{"0000000000000000000000000000000000000000000000000000000000000022"};
    return header;
}

AttemptStats SampleSolveAttemptTimes(const Consensus::Params& params, const CBlockHeader& template_header)
{
    std::vector<double> samples_ms;
    samples_ms.reserve(SAMPLE_COUNT);
    uint32_t successes{0};

    for (uint32_t i = 0; i < SAMPLE_COUNT; ++i) {
        CBlockHeader candidate{template_header};
        candidate.nNonce64 = static_cast<uint64_t>(template_header.nNonce64) + i;
        candidate.nNonce = static_cast<uint32_t>(candidate.nNonce64);

        uint64_t max_tries{1};
        const auto start = std::chrono::steady_clock::now();
        const bool solved = SolveMatMul(candidate, params, max_tries);
        const auto stop = std::chrono::steady_clock::now();
        if (solved) ++successes;

        const auto elapsed =
            std::chrono::duration_cast<std::chrono::duration<double, std::milli>>(stop - start).count();
        samples_ms.push_back(elapsed);
    }

    std::sort(samples_ms.begin(), samples_ms.end());
    const double mean_ms = std::accumulate(samples_ms.begin(), samples_ms.end(), 0.0) / samples_ms.size();
    const double median_ms = 0.5 * (samples_ms[(samples_ms.size() / 2) - 1] + samples_ms[samples_ms.size() / 2]);
    return AttemptStats{mean_ms, median_ms, successes};
}

void RunMatMulSolveBenchmark(benchmark::Bench& bench, uint32_t n, uint32_t b, uint32_t r)
{
    const auto params{BenchmarkConsensus(n, b, r)};
    const auto template_header{BuildTemplateHeader(n)};

    bench.epochs(1).epochIterations(1).run([&] {
        const AttemptStats stats{SampleSolveAttemptTimes(params, template_header)};
        std::cout << std::fixed << std::setprecision(6)
                  << "MatMulSolve[n=" << n << ",b=" << b << ",r=" << r << "] "
                  << "samples=" << SAMPLE_COUNT
                  << " successes=" << stats.successes
                  << " mean_ms=" << stats.mean_ms
                  << " median_ms=" << stats.median_ms
                  << " nBits=0x" << std::hex << EASY_NBITS << std::dec
                  << '\n';
    });
}

void MatMulSolveMainnetDimensions(benchmark::Bench& bench)
{
    RunMatMulSolveBenchmark(bench, /*n=*/512, /*b=*/16, /*r=*/8);
}

void MatMulSolveTestnetDimensions(benchmark::Bench& bench)
{
    RunMatMulSolveBenchmark(bench, /*n=*/256, /*b=*/8, /*r=*/4);
}
} // namespace

BENCHMARK(MatMulSolveMainnetDimensions, benchmark::PriorityLevel::HIGH);
BENCHMARK(MatMulSolveTestnetDimensions, benchmark::PriorityLevel::HIGH);
