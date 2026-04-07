// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <bench/bench.h>
#include <shielded/matrict_plus_backend.h>
#include <shielded/ringct/matrict.h>

#include <cassert>

using namespace shielded::ringct;
namespace matrictplus = shielded::matrictplus;

namespace {

void MatRiCTCreateBench(benchmark::Bench& bench)
{
    const auto fixture = matrictplus::BuildDeterministicFixture();
    assert(fixture.IsValid());

    // The portable fixture keeps bench inputs deterministic so regressions can
    // be compared across hosts without local RNG drift.
    bench.batch(fixture.input_notes.size()).unit("input").minEpochIterations(10).run([&] {
        MatRiCTProof proof;
        const bool ok = matrictplus::CreateProof(proof, fixture);
        ankerl::nanobench::doNotOptimizeAway(ok);
    });
}

void MatRiCTVerifyBench(benchmark::Bench& bench)
{
    const auto fixture = matrictplus::BuildDeterministicFixture();
    assert(fixture.IsValid());

    MatRiCTProof proof;
    const bool created = matrictplus::CreateProof(proof, fixture);
    assert(created);

    // Verification is cheaper than creation but still benefits from
    // multi-iteration epochs on the same deterministic fixture.
    bench.batch(fixture.input_notes.size()).unit("input").minEpochIterations(5).run([&] {
        const bool ok = matrictplus::VerifyProof(proof, fixture);
        ankerl::nanobench::doNotOptimizeAway(ok);
    });
}

} // namespace

BENCHMARK(MatRiCTCreateBench, benchmark::PriorityLevel::HIGH);
BENCHMARK(MatRiCTVerifyBench, benchmark::PriorityLevel::HIGH);
