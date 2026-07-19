// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.
//
// CPU-only combine-algorithm tournament (no GPU). Records classical vs
// deferred vs limb16 / Karatsuba-9 / adaptive-limb wall costs at small test
// dims so ASERT calibration can track the fastest *known exact* path.
// Companion notes: doc/btx-matmul-v4.4-combine-algorithm-tournament.md

#include <bench/bench.h>

#include <matmul/matmul_v4.h>
#include <matmul/matmul_v4_bmx4.h>
#include <random.h>

#include <chrono>
#include <cstdint>
#include <cstdio>
#include <string>
#include <vector>

namespace {

using namespace matmul::v4;
namespace bx = matmul::v4::bmx4;
using Clock = std::chrono::steady_clock;

double Secs(Clock::time_point a, Clock::time_point b)
{
    return std::chrono::duration<double>(b - a).count();
}

struct CombineFixture {
    uint32_t n{0};
    uint32_t m{0};
    std::vector<int32_t> P;
    std::vector<int32_t> Q;
};

CombineFixture MakeFixture(uint32_t n, uint32_t m, int64_t bound, uint64_t seed_burn)
{
    FastRandomContext rng{/*fDeterministic=*/true};
    for (uint64_t i = 0; i < (seed_burn & 0xff); ++i) (void)rng.rand32();
    CombineFixture f;
    f.n = n;
    f.m = m;
    f.P.assign(static_cast<size_t>(m) * n, 0);
    f.Q.assign(static_cast<size_t>(n) * m, 0);
    for (auto& x : f.P) {
        x = static_cast<int32_t>(static_cast<int64_t>(rng.randrange(2 * bound + 1)) - bound);
    }
    for (auto& x : f.Q) {
        x = static_cast<int32_t>(static_cast<int64_t>(rng.randrange(2 * bound + 1)) - bound);
    }
    return f;
}

struct LaneTimes {
    double classical_ms{0};
    double deferred_ms{0};
    double limb16_ms{0};
    double kara9_ms{0};
    double adapt_ms{0};
    bool identity{false};
};

LaneTimes TimeLanes(const CombineFixture& f)
{
    LaneTimes t;
    auto t0 = Clock::now();
    const auto classical = ComputeCombineModQClassical(f.P, f.Q, f.n, f.m);
    auto t1 = Clock::now();
    const auto deferred = ComputeCombineModQ(f.P, f.Q, f.n, f.m);
    auto t2 = Clock::now();
    const auto limb16 = bx::ComputeCombineLimbTensorBMX4C(f.P, f.Q, f.n, f.m);
    auto t3 = Clock::now();
    const auto kara9 = bx::ComputeCombineKaratsuba9BMX4C(f.P, f.Q, f.n, f.m);
    auto t4 = Clock::now();
    const auto adapt = bx::ComputeCombineAdaptiveLimbBMX4C(f.P, f.Q, f.n, f.m);
    auto t5 = Clock::now();

    t.classical_ms = Secs(t0, t1) * 1e3;
    t.deferred_ms = Secs(t1, t2) * 1e3;
    t.limb16_ms = Secs(t2, t3) * 1e3;
    t.kara9_ms = Secs(t3, t4) * 1e3;
    t.adapt_ms = Secs(t4, t5) * 1e3;
    t.identity = (classical == deferred && deferred == limb16 && limb16 == kara9 && kara9 == adapt);
    ankerl::nanobench::doNotOptimizeAway(adapt.front());
    return t;
}

void PrintLaneTable(const char* label, const CombineFixture& f, const LaneTimes& t)
{
    std::printf("\n[combine_tournament] %s n=%u m=%u max_abs=%lld identity=%s\n",
                label, f.n, f.m,
                static_cast<long long>(bx::ScanCombineMaxAbsBMX4C(f.P, f.Q)),
                t.identity ? "PASS" : "FAIL — times VOID");
    std::printf("  classical per-MAC Fq     : %9.3f ms\n", t.classical_ms);
    std::printf("  deferred __int128        : %9.3f ms\n", t.deferred_ms);
    std::printf("  limb-tensor 16 GEMM      : %9.3f ms\n", t.limb16_ms);
    std::printf("  Karatsuba-9              : %9.3f ms\n", t.kara9_ms);
    std::printf("  adaptive limb (miner)    : %9.3f ms\n", t.adapt_ms);
}

} // namespace

static void MatMulV4CombineTournament(benchmark::Bench& bench)
{
    const CombineFixture small = MakeFixture(/*n=*/64, /*m=*/16, /*bound=*/1500, /*seed_burn=*/1);
    const CombineFixture mid = MakeFixture(/*n=*/128, /*m=*/32,
                                           /*bound=*/static_cast<int64_t>(bx::kProjPerMac) * 128,
                                           /*seed_burn=*/2);
    const CombineFixture twolimb = MakeFixture(/*n=*/96, /*m=*/24,
                                               /*bound=*/bx::kCombineTwoLimbBase64MaxAbs,
                                               /*seed_burn=*/3);

    bool printed = false;
    bench.unit("tournament").batch(1).run([&] {
        const LaneTimes a = TimeLanes(small);
        const LaneTimes b = TimeLanes(mid);
        const LaneTimes c = TimeLanes(twolimb);
        if (!printed) {
            PrintLaneTable("small_random", small, a);
            PrintLaneTable("mid_full_envelope", mid, b);
            PrintLaneTable("two_limb_safe", twolimb, c);
            printed = true;
        }
        ankerl::nanobench::doNotOptimizeAway(a.identity && b.identity && c.identity);
    });
}

BENCHMARK(MatMulV4CombineTournament, benchmark::PriorityLevel::HIGH);
