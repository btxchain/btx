// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <bench/bench.h>

#include <matmul/freivalds.h>
#include <matmul/matrix.h>
#include <random.h>
#include <uint256.h>

#include <cstdint>

namespace {

matmul::Matrix RandomSquareMatrix(FastRandomContext& rng, uint32_t n)
{
    matmul::Matrix out(n, n);
    for (uint32_t row = 0; row < n; ++row) {
        for (uint32_t col = 0; col < n; ++col) {
            out.at(row, col) = matmul::field::from_uint32(rng.rand32());
        }
    }
    return out;
}

void BenchFreivalds(benchmark::Bench& bench, uint32_t n, uint32_t rounds)
{
    FastRandomContext rng{/*fDeterministic=*/true};
    const matmul::Matrix A = RandomSquareMatrix(rng, n);
    const matmul::Matrix B = RandomSquareMatrix(rng, n);
    const matmul::Matrix C = matmul::MultiplyBlocked(A, B, /*tile_size=*/16);
    const auto sigma = uint256::FromHex("5c0ab5bace4fd1f2ab297de0765a5af565475d3ade9fc50d67efdf335f17202b").value();

    bench.batch(rounds).unit("round").run([&] {
        const auto result = matmul::freivalds::Verify(A, B, C, sigma, rounds);
        ankerl::nanobench::doNotOptimizeAway(result.passed);
    });
}

void MatMulFreivaldsN256R2(benchmark::Bench& bench)
{
    BenchFreivalds(bench, /*n=*/256, /*rounds=*/2);
}

void MatMulFreivaldsN512R2(benchmark::Bench& bench)
{
    BenchFreivalds(bench, /*n=*/512, /*rounds=*/2);
}

} // namespace

BENCHMARK(MatMulFreivaldsN256R2, benchmark::PriorityLevel::HIGH);
BENCHMARK(MatMulFreivaldsN512R2, benchmark::PriorityLevel::HIGH);
