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

#include <algorithm>
#include <chrono>
#include <cstdint>
#include <iomanip>
#include <iostream>
#include <numeric>
#include <vector>

namespace {
constexpr uint32_t SAMPLE_COUNT{24};
constexpr uint32_t MAINNET_LIVE_LIKE_NBITS{0x1f00b092U};

struct AttemptStats {
    double mean_ms;
    double median_ms;
    uint32_t successes;
};

arith_uint256 SaturatingLeftShiftLocal(const arith_uint256& val, unsigned int shift)
{
    if (shift == 0 || val == arith_uint256(0)) return val;
    if (shift >= 256) return (val == arith_uint256(0)) ? arith_uint256(0) : ~arith_uint256(0);
    arith_uint256 mask = ~arith_uint256(0);
    mask >>= shift;
    if (val > mask) return ~arith_uint256(0);
    return val << shift;
}

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
    header.nTime = 1'741'000'000;
    header.nBits = nbits;
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

void RunMatMulPreHashSolveBenchmark(
    benchmark::Bench& bench,
    const char* label,
    uint32_t n,
    uint32_t b,
    uint32_t r,
    uint32_t nbits,
    uint32_t epsilon_bits)
{
    const auto ungated_params{BenchmarkConsensus(n, b, r, /*epsilon_bits=*/0)};
    const auto gated_params{BenchmarkConsensus(n, b, r, epsilon_bits)};
    const auto template_header{BuildTemplateHeader(n, nbits)};

    double sigma_pass_probability_estimate{0.0};
    if (auto target{DeriveTarget(nbits, gated_params.powLimit)}) {
        constexpr double kTwoToMinus256 = 8.6361685550944446253863518628003995711160003644363e-78;
        const arith_uint256 sigma_target = SaturatingLeftShiftLocal(*target, epsilon_bits);
        sigma_pass_probability_estimate = std::min(1.0, sigma_target.getdouble() * kTwoToMinus256);
    }

    bench.epochs(1).epochIterations(1).run([&] {
        const AttemptStats ungated{SampleSolveAttemptTimes(ungated_params, template_header)};
        const AttemptStats gated{SampleSolveAttemptTimes(gated_params, template_header)};
        const double gated_vs_ungated_cost_share = ungated.mean_ms > 0.0
            ? gated.mean_ms / ungated.mean_ms
            : 0.0;
        const double ungated_over_gated_speedup = gated.mean_ms > 0.0
            ? ungated.mean_ms / gated.mean_ms
            : 0.0;

        std::cout << std::fixed << std::setprecision(6)
                  << "MatMulPreHashSolve[label=" << label
                  << ",n=" << n
                  << ",b=" << b
                  << ",r=" << r
                  << ",nbits=0x" << std::hex << nbits << std::dec
                  << ",epsilon_bits=" << epsilon_bits << "] "
                  << "samples=" << SAMPLE_COUNT
                  << " ungated_mean_ms=" << ungated.mean_ms
                  << " ungated_median_ms=" << ungated.median_ms
                  << " gated_mean_ms=" << gated.mean_ms
                  << " gated_median_ms=" << gated.median_ms
                  << " ungated_successes=" << ungated.successes
                  << " gated_successes=" << gated.successes
                  << " sigma_pass_probability_estimate=" << sigma_pass_probability_estimate
                  << " gated_vs_ungated_cost_share=" << gated_vs_ungated_cost_share
                  << " ungated_over_gated_speedup=" << ungated_over_gated_speedup
                  << '\n';
    });
}

void MatMulPreHashSolveMainnetLiveLikeE10(benchmark::Bench& bench)
{
    RunMatMulPreHashSolveBenchmark(
        bench,
        "mainnet_live_like",
        /*n=*/512,
        /*b=*/16,
        /*r=*/8,
        MAINNET_LIVE_LIKE_NBITS,
        /*epsilon_bits=*/10);
}

void MatMulPreHashSolveMainnetLiveLikeE12(benchmark::Bench& bench)
{
    RunMatMulPreHashSolveBenchmark(
        bench,
        "mainnet_live_like",
        /*n=*/512,
        /*b=*/16,
        /*r=*/8,
        MAINNET_LIVE_LIKE_NBITS,
        /*epsilon_bits=*/12);
}

void MatMulPreHashSolveMainnetLiveLikeE14(benchmark::Bench& bench)
{
    RunMatMulPreHashSolveBenchmark(
        bench,
        "mainnet_live_like",
        /*n=*/512,
        /*b=*/16,
        /*r=*/8,
        MAINNET_LIVE_LIKE_NBITS,
        /*epsilon_bits=*/14);
}

void MatMulPreHashSolveMainnetLiveLikeE16(benchmark::Bench& bench)
{
    RunMatMulPreHashSolveBenchmark(
        bench,
        "mainnet_live_like",
        /*n=*/512,
        /*b=*/16,
        /*r=*/8,
        MAINNET_LIVE_LIKE_NBITS,
        /*epsilon_bits=*/16);
}

void MatMulPreHashSolveMainnetLiveLikeE18(benchmark::Bench& bench)
{
    RunMatMulPreHashSolveBenchmark(
        bench,
        "mainnet_live_like",
        /*n=*/512,
        /*b=*/16,
        /*r=*/8,
        MAINNET_LIVE_LIKE_NBITS,
        /*epsilon_bits=*/18);
}

void MatMulPreHashSolveMainnetLiveLikeE20(benchmark::Bench& bench)
{
    RunMatMulPreHashSolveBenchmark(
        bench,
        "mainnet_live_like",
        /*n=*/512,
        /*b=*/16,
        /*r=*/8,
        MAINNET_LIVE_LIKE_NBITS,
        /*epsilon_bits=*/20);
}

void MatMulPreHashSolveTestnetLiveLikeE10(benchmark::Bench& bench)
{
    RunMatMulPreHashSolveBenchmark(
        bench,
        "testnet_live_like",
        /*n=*/256,
        /*b=*/8,
        /*r=*/4,
        MAINNET_LIVE_LIKE_NBITS,
        /*epsilon_bits=*/10);
}

void MatMulPreHashSolveTestnetLiveLikeE12(benchmark::Bench& bench)
{
    RunMatMulPreHashSolveBenchmark(
        bench,
        "testnet_live_like",
        /*n=*/256,
        /*b=*/8,
        /*r=*/4,
        MAINNET_LIVE_LIKE_NBITS,
        /*epsilon_bits=*/12);
}

void MatMulPreHashSolveTestnetLiveLikeE14(benchmark::Bench& bench)
{
    RunMatMulPreHashSolveBenchmark(
        bench,
        "testnet_live_like",
        /*n=*/256,
        /*b=*/8,
        /*r=*/4,
        MAINNET_LIVE_LIKE_NBITS,
        /*epsilon_bits=*/14);
}

void MatMulPreHashSolveTestnetLiveLikeE16(benchmark::Bench& bench)
{
    RunMatMulPreHashSolveBenchmark(
        bench,
        "testnet_live_like",
        /*n=*/256,
        /*b=*/8,
        /*r=*/4,
        MAINNET_LIVE_LIKE_NBITS,
        /*epsilon_bits=*/16);
}

void MatMulPreHashSolveTestnetLiveLikeE18(benchmark::Bench& bench)
{
    RunMatMulPreHashSolveBenchmark(
        bench,
        "testnet_live_like",
        /*n=*/256,
        /*b=*/8,
        /*r=*/4,
        MAINNET_LIVE_LIKE_NBITS,
        /*epsilon_bits=*/18);
}

void MatMulPreHashSolveTestnetLiveLikeE20(benchmark::Bench& bench)
{
    RunMatMulPreHashSolveBenchmark(
        bench,
        "testnet_live_like",
        /*n=*/256,
        /*b=*/8,
        /*r=*/4,
        MAINNET_LIVE_LIKE_NBITS,
        /*epsilon_bits=*/20);
}
} // namespace

BENCHMARK(MatMulPreHashSolveMainnetLiveLikeE10, benchmark::PriorityLevel::HIGH);
BENCHMARK(MatMulPreHashSolveMainnetLiveLikeE12, benchmark::PriorityLevel::HIGH);
BENCHMARK(MatMulPreHashSolveMainnetLiveLikeE14, benchmark::PriorityLevel::HIGH);
BENCHMARK(MatMulPreHashSolveMainnetLiveLikeE16, benchmark::PriorityLevel::HIGH);
BENCHMARK(MatMulPreHashSolveMainnetLiveLikeE18, benchmark::PriorityLevel::HIGH);
BENCHMARK(MatMulPreHashSolveMainnetLiveLikeE20, benchmark::PriorityLevel::HIGH);
BENCHMARK(MatMulPreHashSolveTestnetLiveLikeE10, benchmark::PriorityLevel::HIGH);
BENCHMARK(MatMulPreHashSolveTestnetLiveLikeE12, benchmark::PriorityLevel::HIGH);
BENCHMARK(MatMulPreHashSolveTestnetLiveLikeE14, benchmark::PriorityLevel::HIGH);
BENCHMARK(MatMulPreHashSolveTestnetLiveLikeE16, benchmark::PriorityLevel::HIGH);
BENCHMARK(MatMulPreHashSolveTestnetLiveLikeE18, benchmark::PriorityLevel::HIGH);
BENCHMARK(MatMulPreHashSolveTestnetLiveLikeE20, benchmark::PriorityLevel::HIGH);
