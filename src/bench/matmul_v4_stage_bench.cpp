// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.
//
// MatMul v4.1 PER-STAGE wall-time harness (design spec §K.2a-WT / §K.2b;
// mirrors the PR #89 reviewer methodology: per-stage timers, bit-exact
// against the reference digest).
//
// The consensus question §K.2a-WT asks is NOT "how many MACs does each stage
// cost" but "what fraction of measured per-nonce MARGINAL wall-time runs on
// tensor units". Under the v4.1 batched-sketch profile (invariant I1') the
// template-scoped work (A, U, V expansion and P = U*A) is amortized over the
// whole nonce sweep, so the marginal per-nonce unit — the thing difficulty
// prices and the thing that decides the hardware ordering — is S1b..S4 below.
// This harness pins the NORMATIVE STAGE BOUNDARIES every backend (CPU here;
// CUDA/HIP/Metal on device) must instrument identically:
//
//   S0   template-scoped work (A,U,V expand + P = U*A; amortized per template)
//   S1b  per-nonce operand expansion (B only — SHA XOF, integer units)
//   S2   per-nonce right GEMM Q = B*V  (tensor units on GPU; stacks across
//        the window as [B_1; ...; B_Q] * V on device)
//   S3a  limb decomposition of P, Qstack (bandwidth-bound elementwise pass)
//   S3b  16 limb-pair GEMMs of P * Qstack (tensor units; Appendix C-13 —
//        the ONE LARGE DENSE GEMM m x Q*m x n of §K.2b)
//   S3c  O(m * Q*m) mod-q recombine     (integer units)
//   S3'  direct mod-q combine           (integer-ALU alternative to S3a-c;
//                                        miners take min(S3a-c, S3') per device)
//   S4   serialize + digest SHA         (integer units)
//
// GO/NO-GO for real silicon (spec §K.2b): on H100/B200 the measured
// (S2 + S3b) share must be the strict majority of per-nonce MARGINAL
// wall-time at window Q >= 32, and the implied batched tensor utilization
// must be >= ~60% of device peak INT8 — otherwise the datacenter ordering
// hypothesized by §K.2b does NOT materialize (the model has been wrong
// twice; only these measurements settle it — anchor: reviewer-measured
// H100/5090 = 0.40x at b=8, n=8192).
//
// Every stage output is cross-checked bit-exact against the single-nonce
// reference (matmul_v4::ComputeDigest), so a backend cannot "win" a stage by
// computing something else.

#include <bench/bench.h>

#include <matmul/int8_field.h>
#include <matmul/matmul_v4.h>
#include <matmul/matmul_v4_batch.h>
#include <matmul/pow_v4.h>
#include <primitives/block.h>
#include <uint256.h>

#include <algorithm>
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <string_view>
#include <vector>

namespace {

using Clock = std::chrono::steady_clock;

double Secs(Clock::time_point a, Clock::time_point b)
{
    return std::chrono::duration<double>(b - a).count();
}

CBlockHeader StageBenchHeader(uint32_t n)
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

struct StageTimes {
    double s0_template{0}, s1b_expand{0}, s2_gemm{0};
    double s3_limb_combine{0}, s3_alu_direct{0}, s4_digest{0};
    bool bit_exact{false};
};

// One full nonce, stage-by-stage, bit-exact against matmul_v4::ComputeDigest.
// (S3a/S3b/S3c are timed together inside ComputeCombineLimbTensor on CPU;
// GPU backends must report S3a / S3b / S3c separately, and must time S2/S3b
// on the STACKED window shapes, not per nonce.)
StageTimes RunStagedNonce(uint32_t n)
{
    StageTimes t;
    uint32_t m = 0;
    if (!matmul::v4::ValidateDims(n, matmul_v4::kTileB, m)) return t;

    const CBlockHeader header = StageBenchHeader(n);

    // S0: template-scoped, paid once per template (invariant I1'). Reported
    // separately and EXCLUDED from the per-nonce marginal total.
    auto c0 = Clock::now();
    const uint256 seed_a = matmul::v4::DeriveOperandSeed(header, matmul::v4::Operand::A);
    const auto [seed_u, seed_v] = matmul::v4::DeriveProjectorSeeds(header);
    const std::vector<int8_t> A = matmul::v4::ExpandOperand(seed_a, n);
    const std::vector<int8_t> U = matmul::v4::ExpandProjector(seed_u, m, n);
    const std::vector<int8_t> V = matmul::v4::ExpandProjector(seed_v, n, m);
    const std::vector<int32_t> P = matmul::v4::ComputeProjectedLeft(U, A, n, m);
    auto c1 = Clock::now();
    t.s0_template = Secs(c0, c1);

    // S1b: per-nonce operand expansion — B only under I1'.
    const uint256 sigma = matmul::v4::DeriveSigma(header);
    const uint256 seed_b = matmul::v4::DeriveOperandSeed(header, matmul::v4::Operand::B);
    const std::vector<int8_t> B = matmul::v4::ExpandOperand(seed_b, n);
    auto c2 = Clock::now();
    t.s1b_expand = Secs(c1, c2);

    // S2: per-nonce right GEMM Q = B*V.
    const std::vector<int32_t> Q = matmul::v4::ComputeProjectedRight(B, V, n, m);
    auto c3 = Clock::now();
    t.s2_gemm = Secs(c2, c3);

    // S3a+S3b+S3c: the limb-tensor combine (window Q=1 slice of the stacked
    // GEMM P * [Q_1 | ... | Q_Q]).
    const auto chat_limb = matmul::v4::ComputeCombineLimbTensor(P, Q, n, m);
    auto c4 = Clock::now();
    t.s3_limb_combine = Secs(c3, c4);

    const auto chat_direct = matmul::v4::ComputeCombineModQ(P, Q, n, m); // S3'
    auto c5 = Clock::now();
    t.s3_alu_direct = Secs(c4, c5);

    const auto payload = matmul::v4::SerializeSketch(chat_limb); // S4
    const uint256 digest = matmul::v4::ComputeSketchDigest(sigma, payload);
    auto c6 = Clock::now();
    t.s4_digest = Secs(c5, c6);

    // Bit-exactness gates (§K.2a-WT: a stage only counts if it computes the
    // consensus bytes).
    uint256 ref_digest;
    std::vector<unsigned char> ref_payload;
    const bool ok = matmul_v4::ComputeDigest(header, n, /*rounds=*/2, ref_digest, ref_payload);
    t.bit_exact = ok && chat_limb == chat_direct && payload == ref_payload && digest == ref_digest;
    return t;
}

void PrintStageTable(uint32_t n, const StageTimes& t)
{
    const double comb = std::min(t.s3_limb_combine, t.s3_alu_direct);
    const char* comb_path = t.s3_limb_combine < t.s3_alu_direct ? "limb-tensor" : "ALU-direct";
    const double total = t.s1b_expand + t.s2_gemm + comb + t.s4_digest; // S0 amortized out
    std::printf("\n[matmul_v4_stage_bench] n=%u b=%u m=%u  (CPU reference; GPU backends mirror these boundaries on STACKED window shapes)\n",
                n, matmul_v4::kTileB, n / matmul_v4::kTileB);
    std::printf("  S0  template A,U,V + P=U*A (amortized)  : %9.3f ms\n", t.s0_template * 1e3);
    std::printf("  S1b per-nonce expand B        (SHA/int) : %9.3f ms  %5.1f%%\n", t.s1b_expand * 1e3, 100 * t.s1b_expand / total);
    std::printf("  S2  per-nonce GEMM Q=B*V      (tensor)  : %9.3f ms  %5.1f%%\n", t.s2_gemm * 1e3, 100 * t.s2_gemm / total);
    std::printf("  S3  combine P*Q, chosen=%-11s      : %9.3f ms  %5.1f%%\n", comb_path, comb * 1e3, 100 * comb / total);
    std::printf("      (limb-tensor %.3f ms vs ALU-direct %.3f ms)\n", t.s3_limb_combine * 1e3, t.s3_alu_direct * 1e3);
    std::printf("  S4  serialize + digest        (SHA/int) : %9.3f ms  %5.1f%%\n", t.s4_digest * 1e3, 100 * t.s4_digest / total);
    std::printf("  per-nonce MARGINAL total (S0 amortized) : %9.3f ms   bit-exact=%s\n",
                total * 1e3, t.bit_exact ? "YES" : "NO -- STAGE OUTPUT DIVERGED, TIMES VOID");
    std::printf("  tensor-stage share (S2+S3 if limb path) : %5.1f%%  [§K.2a-WT majority gate]\n",
                100 * (t.s2_gemm + (t.s3_limb_combine < t.s3_alu_direct ? comb : 0)) / total);
}

void MatMulV4StagesAtDim(benchmark::Bench& bench, uint32_t n)
{
    bool printed = false;
    bench.unit("nonce").run([&] {
        const StageTimes t = RunStagedNonce(n);
        if (!printed) {
            PrintStageTable(n, t);
            printed = true;
        }
        ankerl::nanobench::doNotOptimizeAway(t.bit_exact);
    });
}

void MatMulV4StageN256(benchmark::Bench& bench) { MatMulV4StagesAtDim(bench, 256); }
void MatMulV4StageN512(benchmark::Bench& bench) { MatMulV4StagesAtDim(bench, 512); }

// Heavy lane: production dimension, opt-in (minutes on CPU).
//   BTX_V4_STAGE_BENCH_DIM=4096 ./bench_btx -filter=MatMulV4StageEnvDim
void MatMulV4StageEnvDim(benchmark::Bench& bench)
{
    uint32_t n = 512;
    if (const char* env = std::getenv("BTX_V4_STAGE_BENCH_DIM")) {
        n = static_cast<uint32_t>(std::strtoul(env, nullptr, 10));
    }
    MatMulV4StagesAtDim(bench, n);
}

// Batched-miner throughput at unit-lane dim: template A/U/V + P=U*A
// amortization and the stacked limb-tensor combine, end-to-end
// (BatchedSketchMiner semantics; window Q via BTX_MATMUL_V4_BATCH).
void MatMulV4BatchedMinerN256(benchmark::Bench& bench)
{
    const uint32_t n = 256;
    uint32_t window = matmul::v4::kDefaultMinerBatch;
    if (const char* env = std::getenv("BTX_MATMUL_V4_BATCH")) {
        const uint32_t parsed = static_cast<uint32_t>(std::strtoul(env, nullptr, 10));
        window = std::clamp<uint32_t>(parsed, 1, matmul::v4::kMaxMinerBatch);
    }
    const matmul::v4::BatchedSketchMiner miner{StageBenchHeader(n), n};
    if (!miner.Valid()) return;
    uint64_t nonce = 0;
    bench.batch(window).unit("nonce").run([&] {
        std::vector<matmul::v4::BatchNonceResult> out;
        const bool ok = miner.Mine(nonce, window, out);
        nonce += window;
        ankerl::nanobench::doNotOptimizeAway(ok);
    });
}

} // namespace

BENCHMARK(MatMulV4StageN256, benchmark::PriorityLevel::HIGH);
BENCHMARK(MatMulV4StageN512, benchmark::PriorityLevel::LOW);
BENCHMARK(MatMulV4StageEnvDim, benchmark::PriorityLevel::LOW);
BENCHMARK(MatMulV4BatchedMinerN256, benchmark::PriorityLevel::LOW);
