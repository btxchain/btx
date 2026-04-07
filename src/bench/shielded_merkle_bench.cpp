// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <bench/bench.h>
#include <crypto/sha256.h>
#include <shielded/merkle_tree.h>
#include <streams.h>
#include <uint256.h>

#include <cstdint>

using namespace shielded;

namespace {

/** Deterministic commitment from a counter. */
uint256 BenchCommitment(uint32_t n)
{
    uint256 result;
    unsigned char buf[4];
    buf[0] = n & 0xFF;
    buf[1] = (n >> 8) & 0xFF;
    buf[2] = (n >> 16) & 0xFF;
    buf[3] = (n >> 24) & 0xFF;
    CSHA256().Write(buf, 4).Finalize(result.begin());
    return result;
}

} // anonymous namespace

// ---------------------------------------------------------------------------
// Append single leaf (target: <5us)
// ---------------------------------------------------------------------------
static void ShieldedMerkleAppend(benchmark::Bench& bench)
{
    ShieldedMerkleTree tree;
    uint32_t counter = 0;

    bench.run([&] {
        tree.Append(BenchCommitment(counter++));
    });
}

// ---------------------------------------------------------------------------
// Compute root from frontier (target: <5us)
// ---------------------------------------------------------------------------
static void ShieldedMerkleRoot(benchmark::Bench& bench)
{
    ShieldedMerkleTree tree;
    // Pre-populate with 10,000 leaves so the frontier is non-trivial.
    for (uint32_t i = 0; i < 10000; ++i) {
        tree.Append(BenchCommitment(i));
    }

    bench.run([&] {
        ankerl::nanobench::doNotOptimizeAway(tree.Root());
    });
}

// ---------------------------------------------------------------------------
// Create witness (target: <5us)
// ---------------------------------------------------------------------------
static void ShieldedMerkleWitnessCreate(benchmark::Bench& bench)
{
    ShieldedMerkleTree tree;
    for (uint32_t i = 0; i < 10000; ++i) {
        tree.Append(BenchCommitment(i));
    }

    bench.run([&] {
        ankerl::nanobench::doNotOptimizeAway(tree.Witness());
    });
}

// ---------------------------------------------------------------------------
// Verify witness (target: <5us)
// ---------------------------------------------------------------------------
static void ShieldedMerkleWitnessVerify(benchmark::Bench& bench)
{
    ShieldedMerkleTree tree;
    for (uint32_t i = 0; i < 10000; ++i) {
        tree.Append(BenchCommitment(i));
    }
    uint256 leaf = tree.LastLeaf();
    ShieldedMerkleWitness wit = tree.Witness();
    uint256 root = tree.Root();

    bench.run([&] {
        ankerl::nanobench::doNotOptimizeAway(wit.Verify(leaf, root));
    });
}

// ---------------------------------------------------------------------------
// Append 10,000 leaves sequentially (target: <50ms)
// ---------------------------------------------------------------------------
static void ShieldedMerkleAppend10k(benchmark::Bench& bench)
{
    bench.run([&] {
        ShieldedMerkleTree tree;
        for (uint32_t i = 0; i < 10000; ++i) {
            tree.Append(BenchCommitment(i));
        }
        ankerl::nanobench::doNotOptimizeAway(tree.Root());
    });
}

// ---------------------------------------------------------------------------
// IncrementalUpdate witness after append (target: <5us)
// ---------------------------------------------------------------------------
static void ShieldedMerkleWitnessUpdate(benchmark::Bench& bench)
{
    ShieldedMerkleTree tree;
    for (uint32_t i = 0; i < 10000; ++i) {
        tree.Append(BenchCommitment(i));
    }
    uint256 target_leaf = BenchCommitment(10000);
    tree.Append(target_leaf);
    ShieldedMerkleWitness wit = tree.Witness();

    uint32_t counter = 10001;
    bench.run([&] {
        uint256 cm = BenchCommitment(counter++);
        tree.Append(cm);
        wit.IncrementalUpdate(cm);
    });
}

// ---------------------------------------------------------------------------
// Serialize/deserialize tree (target: <10us)
// ---------------------------------------------------------------------------
static void ShieldedMerkleSerialize(benchmark::Bench& bench)
{
    ShieldedMerkleTree tree;
    for (uint32_t i = 0; i < 10000; ++i) {
        tree.Append(BenchCommitment(i));
    }

    bench.run([&] {
        DataStream ss{};
        ss << tree;
        ShieldedMerkleTree tree2;
        ss >> tree2;
        ankerl::nanobench::doNotOptimizeAway(tree2.Size());
    });
}

// ---------------------------------------------------------------------------
// Register benchmarks
// ---------------------------------------------------------------------------

BENCHMARK(ShieldedMerkleAppend, benchmark::PriorityLevel::HIGH);
BENCHMARK(ShieldedMerkleRoot, benchmark::PriorityLevel::HIGH);
BENCHMARK(ShieldedMerkleWitnessCreate, benchmark::PriorityLevel::HIGH);
BENCHMARK(ShieldedMerkleWitnessVerify, benchmark::PriorityLevel::HIGH);
BENCHMARK(ShieldedMerkleAppend10k, benchmark::PriorityLevel::HIGH);
BENCHMARK(ShieldedMerkleWitnessUpdate, benchmark::PriorityLevel::HIGH);
BENCHMARK(ShieldedMerkleSerialize, benchmark::PriorityLevel::HIGH);
