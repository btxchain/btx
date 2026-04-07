// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

//
// Genesis Calibration Benchmark Suite
//
// Measures solve-attempt timing at MAINNET powLimit difficulty to determine
// whether the genesis difficulty calibration produces ~0.25s blocks during the
// fast-mining phase and ~90s blocks during normal operation.
//
// This benchmark answers three critical pre-launch questions:
// 1. What is the per-attempt solve time at mainnet dimensions (n=512)?
// 2. How many attempts per second can this hardware sustain?
// 3. Given powLimit target, what is the expected block interval?
//
// Run with:  bench_btx -filter='MatMulGenesis*'
//

#include <bench/bench.h>

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

#include <algorithm>
#include <chrono>
#include <cmath>
#include <cstdint>
#include <iomanip>
#include <iostream>
#include <numeric>
#include <string>
#include <vector>

namespace {

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

struct CalibrationConfig {
    std::string label;
    uint32_t n;           // matrix dimension
    uint32_t b;           // transcript block size
    uint32_t r;           // noise rank
    uint32_t nbits;       // difficulty (compact target)
    uint256 pow_limit;    // chain powLimit
    uint32_t samples;     // number of single-attempt timing samples
};

CalibrationConfig MainnetConfig()
{
    return CalibrationConfig{
        .label = "mainnet",
        .n = 512,
        .b = 16,
        .r = 8,
        .nbits = 0x20147ae1U,
        .pow_limit = uint256{"147ae147ae147ae147ae147ae147ae147ae147ae147ae147ae147ae147ae1470"},
        .samples = 50,
    };
}

CalibrationConfig TestnetConfig()
{
    return CalibrationConfig{
        .label = "testnet",
        .n = 256,
        .b = 8,
        .r = 4,
        .nbits = 0x20027525U,
        .pow_limit = uint256{"027525460aa64c2f837b4a2339c0ebedfa43fe5c91d14e3bcd35a858793dd970"},
        .samples = 50,
    };
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

Consensus::Params ConsensusForConfig(const CalibrationConfig& cfg)
{
    ArgsManager args;
    auto params{CreateChainParams(args, ChainType::REGTEST)->GetConsensus()};
    params.fMatMulPOW = true;
    params.nMatMulDimension = cfg.n;
    params.nMatMulTranscriptBlockSize = cfg.b;
    params.nMatMulNoiseRank = cfg.r;
    params.powLimit = cfg.pow_limit;
    return params;
}

CBlockHeader BuildCalibrationHeader(const CalibrationConfig& cfg, uint64_t nonce)
{
    CBlockHeader header{};
    header.nVersion = 1;
    header.nTime = 1'738'800'000;
    header.nBits = cfg.nbits;
    header.nNonce = static_cast<uint32_t>(nonce);
    header.nNonce64 = nonce;
    header.hashPrevBlock = uint256{"0000000000000000000000000000000000000000000000000000000000000001"};
    header.hashMerkleRoot = uint256{"0000000000000000000000000000000000000000000000000000000000000002"};
    header.matmul_dim = static_cast<uint16_t>(cfg.n);
    header.seed_a = uint256{"0000000000000000000000000000000000000000000000000000000000000011"};
    header.seed_b = uint256{"0000000000000000000000000000000000000000000000000000000000000022"};
    return header;
}

struct TimingStats {
    double mean_ms;
    double median_ms;
    double p5_ms;
    double p95_ms;
    double min_ms;
    double max_ms;
    double stddev_ms;
    uint32_t sample_count;
};

TimingStats ComputeStats(std::vector<double>& samples)
{
    std::sort(samples.begin(), samples.end());
    const size_t n = samples.size();
    const double sum = std::accumulate(samples.begin(), samples.end(), 0.0);
    const double mean = sum / static_cast<double>(n);

    double variance = 0.0;
    for (double s : samples) {
        variance += (s - mean) * (s - mean);
    }
    variance /= static_cast<double>(n);

    return TimingStats{
        .mean_ms = mean,
        .median_ms = (n % 2 == 0)
            ? 0.5 * (samples[n / 2 - 1] + samples[n / 2])
            : samples[n / 2],
        .p5_ms = samples[static_cast<size_t>(static_cast<double>(n) * 0.05)],
        .p95_ms = samples[static_cast<size_t>(static_cast<double>(n) * 0.95)],
        .min_ms = samples.front(),
        .max_ms = samples.back(),
        .stddev_ms = std::sqrt(variance),
        .sample_count = static_cast<uint32_t>(n),
    };
}

// ---------------------------------------------------------------------------
// Component Breakdown: measure each phase of a single solve attempt
// ---------------------------------------------------------------------------

struct ComponentTiming {
    double matrix_gen_ms;    // FromSeed for A and B
    double noise_gen_ms;     // noise::Generate
    double noise_mul_ms;     // E_L*E_R, F_L*F_R, additions
    double matmul_ms;        // CanonicalMatMul (the dominant cost)
    double total_ms;         // end-to-end single attempt
};

ComponentTiming MeasureComponents(const CalibrationConfig& cfg)
{
    CBlockHeader header = BuildCalibrationHeader(cfg, 42);
    ComponentTiming ct{};

    auto t0 = std::chrono::steady_clock::now();
    const auto A = matmul::FromSeed(header.seed_a, cfg.n);
    const auto B = matmul::FromSeed(header.seed_b, cfg.n);
    auto t1 = std::chrono::steady_clock::now();
    ct.matrix_gen_ms = std::chrono::duration<double, std::milli>(t1 - t0).count();

    const uint256 sigma = matmul::DeriveSigma(header);

    auto t2 = std::chrono::steady_clock::now();
    const auto np = matmul::noise::Generate(sigma, cfg.n, cfg.r);
    auto t3 = std::chrono::steady_clock::now();
    ct.noise_gen_ms = std::chrono::duration<double, std::milli>(t3 - t2).count();

    auto t4 = std::chrono::steady_clock::now();
    const auto A_prime = A + (np.E_L * np.E_R);
    const auto B_prime = B + (np.F_L * np.F_R);
    auto t5 = std::chrono::steady_clock::now();
    ct.noise_mul_ms = std::chrono::duration<double, std::milli>(t5 - t4).count();

    auto t6 = std::chrono::steady_clock::now();
    (void)matmul::transcript::CanonicalMatMul(A_prime, B_prime, cfg.b, sigma);
    auto t7 = std::chrono::steady_clock::now();
    ct.matmul_ms = std::chrono::duration<double, std::milli>(t7 - t6).count();

    ct.total_ms = std::chrono::duration<double, std::milli>(t7 - t0).count();
    return ct;
}

// ---------------------------------------------------------------------------
// Solve-attempt sampling: time single SolveMatMul(max_tries=1) calls
// ---------------------------------------------------------------------------

TimingStats SampleSolveAttempts(const CalibrationConfig& cfg, const Consensus::Params& params)
{
    std::vector<double> samples;
    samples.reserve(cfg.samples);

    for (uint32_t i = 0; i < cfg.samples; ++i) {
        CBlockHeader candidate = BuildCalibrationHeader(cfg, 1000 + i);
        uint64_t max_tries = 1;

        const auto start = std::chrono::steady_clock::now();
        (void)SolveMatMul(candidate, params, max_tries);
        const auto stop = std::chrono::steady_clock::now();

        samples.push_back(std::chrono::duration<double, std::milli>(stop - start).count());
    }

    return ComputeStats(samples);
}

// ---------------------------------------------------------------------------
// Phase 2 verification timing
// ---------------------------------------------------------------------------

TimingStats SamplePhase2Verification(const CalibrationConfig& cfg, const Consensus::Params& params)
{
    // First, find a solved block to verify
    CBlockHeader solved = BuildCalibrationHeader(cfg, 77777);
    // Use very easy difficulty to guarantee a quick solve for the template
    Consensus::Params easy_params = params;
    easy_params.powLimit = uint256{"ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"};
    solved.nBits = UintToArith256(easy_params.powLimit).GetCompact();
    uint64_t max_tries = 1000;
    bool ok = SolveMatMul(solved, easy_params, max_tries);
    if (!ok) return TimingStats{};

    std::vector<double> samples;
    samples.reserve(cfg.samples);

    for (uint32_t i = 0; i < cfg.samples; ++i) {
        const auto start = std::chrono::steady_clock::now();
        (void)CheckMatMulProofOfWork_Phase2(solved, easy_params);
        const auto stop = std::chrono::steady_clock::now();
        samples.push_back(std::chrono::duration<double, std::milli>(stop - start).count());
    }

    return ComputeStats(samples);
}

// ---------------------------------------------------------------------------
// Expected block interval calculation
// ---------------------------------------------------------------------------

struct BlockIntervalEstimate {
    double attempts_per_second;
    double success_probability;    // probability a single attempt meets target
    double expected_attempts;      // 1/probability
    double expected_block_time_s;  // expected_attempts * attempt_time
    double fast_phase_total_hours; // 50,000 blocks at expected rate
};

BlockIntervalEstimate EstimateBlockInterval(
    const CalibrationConfig& cfg,
    double attempt_time_ms)
{
    BlockIntervalEstimate est{};

    est.attempts_per_second = 1000.0 / attempt_time_ms;

    // Target probability: target_value / 2^256
    // For compact nBits, decode to a 256-bit target
    arith_uint256 target;
    target.SetCompact(cfg.nbits);
    // Approximate: target / 2^256
    // Use log to avoid overflow: P = 2^(log2(target) - 256)
    const double log2_target = std::log2(target.getdouble());
    const double log2_probability = log2_target - 256.0;
    est.success_probability = std::pow(2.0, log2_probability);

    est.expected_attempts = 1.0 / est.success_probability;
    est.expected_block_time_s = est.expected_attempts * (attempt_time_ms / 1000.0);
    est.fast_phase_total_hours = (50000.0 * est.expected_block_time_s) / 3600.0;

    return est;
}

// ---------------------------------------------------------------------------
// Report generation
// ---------------------------------------------------------------------------

void PrintReport(
    const CalibrationConfig& cfg,
    const ComponentTiming& components,
    const TimingStats& solve_stats,
    const TimingStats& verify_stats,
    const BlockIntervalEstimate& estimate)
{
    std::cout << "\n"
              << "================================================================\n"
              << "  GENESIS CALIBRATION REPORT: " << cfg.label << "\n"
              << "  Matrix dimensions: n=" << cfg.n << " b=" << cfg.b << " r=" << cfg.r << "\n"
              << "  Difficulty (nBits): 0x" << std::hex << cfg.nbits << std::dec << "\n"
              << "================================================================\n\n";

    std::cout << std::fixed << std::setprecision(3);

    // Component breakdown
    std::cout << "--- Component Breakdown (single attempt) ---\n"
              << "  Matrix generation (2x FromSeed): " << components.matrix_gen_ms << " ms\n"
              << "  Noise generation:                " << components.noise_gen_ms << " ms\n"
              << "  Noise multiplication + addition: " << components.noise_mul_ms << " ms\n"
              << "  Canonical MatMul (transcript):   " << components.matmul_ms << " ms\n"
              << "  Total single attempt:            " << components.total_ms << " ms\n\n";

    // Solve timing
    std::cout << "--- Solve Attempt Timing (SolveMatMul, max_tries=1) ---\n"
              << "  Samples:  " << solve_stats.sample_count << "\n"
              << "  Mean:     " << solve_stats.mean_ms << " ms\n"
              << "  Median:   " << solve_stats.median_ms << " ms\n"
              << "  Stddev:   " << solve_stats.stddev_ms << " ms\n"
              << "  P5:       " << solve_stats.p5_ms << " ms\n"
              << "  P95:      " << solve_stats.p95_ms << " ms\n"
              << "  Min:      " << solve_stats.min_ms << " ms\n"
              << "  Max:      " << solve_stats.max_ms << " ms\n\n";

    // Phase 2 verification timing
    std::cout << "--- Phase 2 Verification Timing ---\n"
              << "  Samples:  " << verify_stats.sample_count << "\n"
              << "  Mean:     " << verify_stats.mean_ms << " ms\n"
              << "  Median:   " << verify_stats.median_ms << " ms\n"
              << "  P95:      " << verify_stats.p95_ms << " ms\n\n";

    // Block interval estimate
    std::cout << "--- Block Interval Estimate ---\n"
              << "  Attempts/second (this hardware): " << std::setprecision(2) << estimate.attempts_per_second << "\n"
              << "  Success probability per attempt:  " << std::scientific << estimate.success_probability << "\n"
              << "  Expected attempts per block:      " << std::fixed << std::setprecision(1) << estimate.expected_attempts << "\n"
              << "  Expected block time:              " << std::setprecision(3) << estimate.expected_block_time_s << " seconds\n\n";

    // SLA assessment
    std::cout << "--- SLA Assessment ---\n";
    const double fast_target = 0.25;
    const double normal_target = 90.0;
    const double block_time = estimate.expected_block_time_s;

    std::cout << std::fixed << std::setprecision(3);
    std::cout << "  Fast phase target:  " << fast_target << "s  |  Estimated: " << block_time << "s";
    if (block_time < fast_target * 0.5) {
        std::cout << "  [FAST - blocks arrive faster than target]";
    } else if (block_time > fast_target * 2.0) {
        std::cout << "  [SLOW - blocks arrive slower than target]";
    } else {
        std::cout << "  [OK]";
    }
    std::cout << "\n";

    std::cout << "  Normal phase would need " << std::setprecision(1)
              << (normal_target / block_time) << "x hashrate reduction (via difficulty increase)\n";

    std::cout << "  Fast phase (50,000 blocks): " << std::setprecision(2)
              << estimate.fast_phase_total_hours << " hours estimated\n";

    // Go/no-go
    std::cout << "\n--- VERDICT ---\n";
    if (block_time >= fast_target * 0.1 && block_time <= fast_target * 10.0) {
        std::cout << "  PASS: powLimit difficulty is within reasonable range for genesis.\n";
        if (block_time > fast_target * 2.0) {
            std::cout << "  NOTE: Blocks will be slower than 0.25s target. Consider easing powLimit.\n";
        } else if (block_time < fast_target * 0.5) {
            std::cout << "  NOTE: Blocks will be faster than 0.25s target. Consider tightening powLimit.\n";
        }
    } else {
        std::cout << "  FAIL: powLimit difficulty is miscalibrated for this hardware.\n";
        std::cout << "  Expected block time " << block_time << "s is too far from 0.25s target.\n";
    }

    // Verification budget check
    const double verify_time_s = verify_stats.mean_ms / 1000.0;
    const double max_verifications_per_min = 60.0 / verify_time_s;
    std::cout << "\n  Phase 2 verification budget: " << std::setprecision(1)
              << max_verifications_per_min << " verifications/min possible\n"
              << "  (mainnet budget: 8/min/peer -> "
              << (max_verifications_per_min >= 8.0 ? "OK" : "INSUFFICIENT") << ")\n";

    std::cout << "\n================================================================\n\n";
}

// ---------------------------------------------------------------------------
// Benchmark entry points
// ---------------------------------------------------------------------------

void RunCalibration(benchmark::Bench& bench, const CalibrationConfig& cfg)
{
    const auto params = ConsensusForConfig(cfg);

    bench.epochs(1).epochIterations(1).run([&] {
        // 1. Component breakdown
        const auto components = MeasureComponents(cfg);

        // 2. Solve-attempt timing distribution
        auto solve_stats = SampleSolveAttempts(cfg, params);

        // 3. Phase 2 verification timing
        auto verify_stats = SamplePhase2Verification(cfg, params);

        // 4. Block interval estimation
        const auto estimate = EstimateBlockInterval(cfg, solve_stats.mean_ms);

        // 5. Print full report
        PrintReport(cfg, components, solve_stats, verify_stats, estimate);
    });
}

void MatMulGenesisCalibrationMainnet(benchmark::Bench& bench)
{
    RunCalibration(bench, MainnetConfig());
}

void MatMulGenesisCalibrationTestnet(benchmark::Bench& bench)
{
    RunCalibration(bench, TestnetConfig());
}

} // namespace

BENCHMARK(MatMulGenesisCalibrationMainnet, benchmark::PriorityLevel::HIGH);
BENCHMARK(MatMulGenesisCalibrationTestnet, benchmark::PriorityLevel::HIGH);
