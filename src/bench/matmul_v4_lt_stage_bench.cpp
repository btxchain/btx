// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.
//
// ENC-DR-LT per-stage wall-time harness (MatExpand + Q* boundaries).
// Mirrors matmul_v4_stage_bench.cpp / matmul-v4-report --profile bmx4c-lt:
//
//   S0  template MatExpand-A + U,V + P=U*A (I1' amortized)
//   S1  per-nonce MatExpand-B              (tensor)
//   S2  per-nonce Bhat*V                   (tensor)
//   S3  combine P*Q                        (int)
//   S4  serialize + digest                 (SHA/int)
//   S5  Q* Merkle + SealWindowCommit       (window-level sample)
//
// Production silicon: prefer contrib/matmul-v4/measure-hardware.sh --profile
// bmx4c-lt (schema_version 3 JSON). This bench is a local CPU stage probe.
//   BTX_V4_LT_STAGE_BENCH_DIM=4096 ./bench_btx -filter=MatMulV4LTStageEnvDim

#include <bench/bench.h>

#include <matmul/matmul_v4.h>
#include <matmul/matmul_v4_bmx4.h>
#include <matmul/matmul_v4_lt.h>
#include <primitives/block.h>
#include <span.h>
#include <uint256.h>

#include <chrono>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <vector>

namespace {

using Clock = std::chrono::steady_clock;
namespace lt = matmul::v4::lt;

double Secs(Clock::time_point a, Clock::time_point b)
{
    return std::chrono::duration<double>(b - a).count();
}

CBlockHeader LTStageHeader(uint32_t n)
{
    CBlockHeader header;
    header.nVersion = 0x20000004;
    header.hashPrevBlock = uint256::FromHex("1111111111111111111111111111111111111111111111111111111111111111").value();
    header.hashMerkleRoot = uint256::FromHex("2222222222222222222222222222222222222222222222222222222222222222").value();
    header.nTime = 1'770'000'090U;
    header.nBits = 0x207fffff;
    header.nNonce64 = 7;
    header.nNonce = 7;
    header.matmul_dim = static_cast<uint16_t>(n);
    header.seed_a = uint256::FromHex("0000000000000000000000000000000000000000000000000000000000000000").value();
    header.seed_b = uint256::FromHex("4504d44d861b69197db1d95e473442346c4f2bc1f5869996bdccd63cfbdbd150").value();
    return header;
}

struct LTStageTimes {
    double s0{0}, s1{0}, s2{0}, s3{0}, s4{0}, s5{0};
    bool bit_exact{false};
};

LTStageTimes RunStagedLTNonce(uint32_t n)
{
    LTStageTimes t;
    uint32_t m = 0;
    if (!lt::ValidateDimsBMX4CLT(n, m)) return t;

    const CBlockHeader header = LTStageHeader(n);

    auto c0 = Clock::now();
    const auto [seed_u, seed_v] = lt::DeriveProjectorSeedsBMX4CLT(header);
    const auto Ahat = lt::ExpandOperandAMatExpand(header, n);
    const auto U = matmul::v4::bmx4::ExpandProjectorBMX4C(seed_u, m, n);
    const auto V = matmul::v4::bmx4::ExpandProjectorBMX4C(seed_v, n, m);
    const auto P = matmul::v4::ComputeProjectedLeft(U, Ahat, n, m);
    auto c1 = Clock::now();
    t.s0 = Secs(c0, c1);

    const uint256 sigma = matmul::v4::DeriveSigma(header);
    const auto Bhat = lt::ExpandOperandBMatExpand(header, n);
    auto c2 = Clock::now();
    t.s1 = Secs(c1, c2);

    const auto Q = matmul::v4::ComputeProjectedRight(Bhat, V, n, m);
    auto c3 = Clock::now();
    t.s2 = Secs(c2, c3);

    const auto Chat = matmul::v4::ComputeCombineModQ(P, Q, n, m);
    auto c4 = Clock::now();
    t.s3 = Secs(c3, c4);

    const auto payload = matmul::v4::SerializeSketch(Chat);
    const uint256 digest = matmul::v4::ComputeSketchDigest(sigma, payload);
    auto c5 = Clock::now();
    t.s4 = Secs(c4, c5);

    const uint256 merkle = lt::ComputeWindowMerkleRoot(Span<const uint256>{&digest, 1});
    const uint256 seal = lt::SealWindowCommit(sigma, merkle, /*Qstar=*/1);
    auto c6 = Clock::now();
    t.s5 = Secs(c5, c6);
    (void)seal;

    uint256 ref;
    std::vector<unsigned char> ref_p;
    t.bit_exact = lt::ComputeDigestBMX4CLT(header, n, ref, ref_p) && ref == digest && ref_p == payload;
    return t;
}

void PrintLT(uint32_t n, const LTStageTimes& t)
{
    const double marginal = t.s1 + t.s2 + t.s3 + t.s4;
    const double tensor = t.s1 + t.s2;
    std::printf("\n[matmul_v4_lt_stage_bench] n=%u b=%u m=%u\n", n, lt::kTileBLT, n / lt::kTileBLT);
    std::printf("  S0  MatExpand-A + U,V + P (I1' amortized): %9.3f ms\n", t.s0 * 1e3);
    std::printf("  S1  MatExpand-B                 (tensor) : %9.3f ms  %5.1f%%\n",
                t.s1 * 1e3, marginal > 0 ? 100 * t.s1 / marginal : 0);
    std::printf("  S2  Bhat*V                      (tensor) : %9.3f ms  %5.1f%%\n",
                t.s2 * 1e3, marginal > 0 ? 100 * t.s2 / marginal : 0);
    std::printf("  S3  combine P*Q                 (int)    : %9.3f ms  %5.1f%%\n",
                t.s3 * 1e3, marginal > 0 ? 100 * t.s3 / marginal : 0);
    std::printf("  S4  digest                      (SHA/int): %9.3f ms  %5.1f%%\n",
                t.s4 * 1e3, marginal > 0 ? 100 * t.s4 / marginal : 0);
    std::printf("  S5  seal sample (Q=1)                    : %9.3f ms\n", t.s5 * 1e3);
    std::printf("  marginal total                           : %9.3f ms  bit-exact=%s\n",
                marginal * 1e3, t.bit_exact ? "YES" : "NO");
    std::printf("  tensor share (S1+S2)                     : %5.1f%%\n",
                marginal > 0 ? 100 * tensor / marginal : 0);
}

void MatMulV4LTStagesAtDim(benchmark::Bench& bench, uint32_t n)
{
    bool printed = false;
    bench.unit("nonce").run([&] {
        const LTStageTimes t = RunStagedLTNonce(n);
        if (!printed) {
            PrintLT(n, t);
            printed = true;
        }
        ankerl::nanobench::doNotOptimizeAway(t.bit_exact);
    });
}

void MatMulV4LTStageN64(benchmark::Bench& bench) { MatMulV4LTStagesAtDim(bench, 64); }
void MatMulV4LTStageN128(benchmark::Bench& bench) { MatMulV4LTStagesAtDim(bench, 128); }

void MatMulV4LTStageEnvDim(benchmark::Bench& bench)
{
    uint32_t n = 64;
    if (const char* env = std::getenv("BTX_V4_LT_STAGE_BENCH_DIM")) {
        n = static_cast<uint32_t>(std::strtoul(env, nullptr, 10));
    }
    MatMulV4LTStagesAtDim(bench, n);
}

} // namespace

BENCHMARK(MatMulV4LTStageN64, benchmark::PriorityLevel::HIGH);
BENCHMARK(MatMulV4LTStageN128, benchmark::PriorityLevel::LOW);
BENCHMARK(MatMulV4LTStageEnvDim, benchmark::PriorityLevel::LOW);
