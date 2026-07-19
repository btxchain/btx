// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit-license.php.
//
// Miner-local combine tournament hook. It compares the canonical deferred
// direct combine with the exact adaptive balanced-base-256 prototype on real
// BMX4 projected matrices. Both outputs are checked before timing.

#include <bench/bench.h>

#include <matmul/matmul_v4.h>
#include <matmul/matmul_v4_bmx4.h>
#include <uint256.h>

#include <cstdint>
#include <stdexcept>
#include <vector>

namespace {

namespace bx = matmul::v4::bmx4;

struct CombineInputs {
    uint32_t n;
    uint32_t m;
    std::vector<int32_t> p;
    std::vector<int32_t> q;
};

CombineInputs MakeCombineInputs(uint32_t n)
{
    uint32_t m = 0;
    if (!bx::ValidateDimsBMX4C(n, matmul::v4::kTileB, m)) {
        throw std::runtime_error("invalid BMX4 combine benchmark dimension");
    }
    const auto sa = uint256::FromHex(
        "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef").value();
    const auto sb = uint256::FromHex(
        "fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210").value();
    const auto su = uint256::FromHex(
        "1111111111111111111111111111111111111111111111111111111111111111").value();
    const auto sv = uint256::FromHex(
        "2222222222222222222222222222222222222222222222222222222222222222").value();
    const auto a = bx::ExpandOperandA(sa, n);
    const auto b = bx::ExpandOperandB(sb, n);
    const auto u = bx::ExpandProjectorBMX4C(su, m, n);
    const auto v = bx::ExpandProjectorBMX4C(sv, n, m);
    return {n, m,
            matmul::v4::ComputeProjectedLeft(u, a, n, m),
            matmul::v4::ComputeProjectedRight(b, v, n, m)};
}

void DirectCombineN128(benchmark::Bench& bench)
{
    const auto in = MakeCombineInputs(128);
    bench.batch(static_cast<double>(in.m) * in.m * in.n).unit("MAC").run([&] {
        const auto out = matmul::v4::ComputeCombineModQ(in.p, in.q, in.n, in.m);
        ankerl::nanobench::doNotOptimizeAway(out.data());
    });
}

void AdaptiveBase256CombineN128(benchmark::Bench& bench)
{
    const auto in = MakeCombineInputs(128);
    bx::AdaptiveCombineStatsBMX4C stats;
    const auto expected = matmul::v4::ComputeCombineModQ(in.p, in.q, in.n, in.m);
    const auto probe = bx::ComputeCombineAdaptiveSparseBase256BMX4C(
        in.p, in.q, in.n, in.m, &stats);
    if (probe != expected || stats.used_sparse_high_correction || stats.used_direct_fallback) {
        throw std::runtime_error("adaptive BMX4 combine benchmark failed exact/common-path gate");
    }
    bench.batch(static_cast<double>(in.m) * in.m * in.n).unit("MAC").run([&] {
        const auto out = bx::ComputeCombineAdaptiveSparseBase256BMX4C(
            in.p, in.q, in.n, in.m, nullptr);
        ankerl::nanobench::doNotOptimizeAway(out.data());
    });
}

} // namespace

BENCHMARK(DirectCombineN128, benchmark::PriorityLevel::LOW);
BENCHMARK(AdaptiveBase256CombineN128, benchmark::PriorityLevel::LOW);
