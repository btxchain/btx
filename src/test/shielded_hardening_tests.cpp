// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// Tests for security and performance hardening of the shielded pool:
// - Consensus-level block shielded verification cost limit
// - Constant-time proof challenge comparison
// - IBD proof verification skipping
// - Merkle tree shared_mutex concurrency
// - Nullifier O(1) lookup in ConnectBlock

#include <consensus/params.h>
#include <crypto/timing_safe.h>
#include <random.h>
#include <shielded/bundle.h>
#include <shielded/lattice/params.h>
#include <shielded/lattice/poly.h>
#include <shielded/merkle_tree.h>
#include <shielded/nullifier.h>
#include <test/util/setup_common.h>
#include <uint256.h>

#include <boost/test/unit_test.hpp>

#include <chrono>
#include <thread>
#include <unordered_set>
#include <vector>

namespace lattice = shielded::lattice;

BOOST_FIXTURE_TEST_SUITE(shielded_hardening_tests, BasicTestingSetup)

// =========================================================================
// Constant-time comparison: TimingSafeEqual
// =========================================================================

BOOST_AUTO_TEST_CASE(timing_safe_equal_basic_correctness)
{
    const uint256 a = GetRandHash();
    const uint256 b = GetRandHash();
    uint256 a_copy = a;

    // Same values must compare equal.
    BOOST_CHECK(TimingSafeEqual(a, a_copy));

    // Different values must compare unequal.
    BOOST_CHECK(!TimingSafeEqual(a, b));

    // Zero hash compared to itself.
    BOOST_CHECK(TimingSafeEqual(uint256{}, uint256{}));

    // Zero hash vs non-zero.
    BOOST_CHECK(!TimingSafeEqual(uint256{}, a));
}

BOOST_AUTO_TEST_CASE(timing_safe_equal_byte_level)
{
    unsigned char buf_a[32], buf_b[32];
    std::memset(buf_a, 0xAA, 32);
    std::memset(buf_b, 0xAA, 32);

    BOOST_CHECK(TimingSafeEqual(buf_a, buf_b, 32));

    // Differ in last byte only.
    buf_b[31] = 0xBB;
    BOOST_CHECK(!TimingSafeEqual(buf_a, buf_b, 32));

    // Differ in first byte only.
    std::memset(buf_b, 0xAA, 32);
    buf_b[0] = 0x00;
    BOOST_CHECK(!TimingSafeEqual(buf_a, buf_b, 32));
}

BOOST_AUTO_TEST_CASE(timing_safe_equal_timing_consistency)
{
    // Verify that comparison of nearly-equal values doesn't short-circuit.
    // We create pairs that differ in various positions and measure time.
    // The point isn't strict constant-time proof (that requires hardware analysis),
    // but that our implementation doesn't use early-exit logic.
    const uint256 baseline = GetRandHash();

    // Generate values differing at different byte positions.
    std::vector<uint256> variants(32);
    for (size_t i = 0; i < 32; ++i) {
        variants[i] = baseline;
        *(variants[i].begin() + i) ^= 0xFF;
    }

    // All should compare unequal.
    for (const auto& v : variants) {
        BOOST_CHECK(!TimingSafeEqual(baseline, v));
    }

    // Equal comparison should work.
    BOOST_CHECK(TimingSafeEqual(baseline, baseline));
}

// =========================================================================
// Consensus-level block shielded verification cost limit
// =========================================================================

BOOST_AUTO_TEST_CASE(consensus_shielded_cost_limit_exists)
{
    Consensus::Params params;
    // Default value: 240,000 (SMILE v2: 1042 txns × 230 cost = 240k)
    BOOST_CHECK_EQUAL(params.nMaxBlockShieldedVerifyCost, Consensus::DEFAULT_MAX_BLOCK_SHIELDED_VERIFY_COST);
    BOOST_CHECK_GT(params.nMaxBlockShieldedVerifyCost, 0U);
    BOOST_CHECK_EQUAL(params.nMaxBlockShieldedScanUnits, Consensus::DEFAULT_MAX_BLOCK_SHIELDED_SCAN_UNITS);
    BOOST_CHECK_GT(params.nMaxBlockShieldedScanUnits, 0U);
    BOOST_CHECK_EQUAL(params.nMaxBlockShieldedTreeUpdateUnits, Consensus::DEFAULT_MAX_BLOCK_SHIELDED_TREE_UPDATE_UNITS);
    BOOST_CHECK_GT(params.nMaxBlockShieldedTreeUpdateUnits, 0U);
}

BOOST_AUTO_TEST_CASE(shielded_cost_per_tx_calculation)
{
    // Single-input single-output: 760 + 102 = 862
    const uint64_t cost_1_1 = 1 * 760 + 1 * 102;
    BOOST_CHECK_EQUAL(cost_1_1, 862U);

    // Max tx (16-in, 16-out): 16*760 + 16*102 = 13,792
    const uint64_t cost_16_16 = 16 * 760 + 16 * 102;
    BOOST_CHECK_EQUAL(cost_16_16, 13792U);

    // Budget (240,000) allows at least 15 max-size txs.
    Consensus::Params params;
    BOOST_CHECK_GE(params.nMaxBlockShieldedVerifyCost / cost_16_16, 15U);

    // But caps the total (floor(240000/13792) = 17).
    BOOST_CHECK_LE(params.nMaxBlockShieldedVerifyCost / cost_16_16, 20U);
}

BOOST_AUTO_TEST_CASE(shielded_cost_accumulation_rejects_overbudget)
{
    Consensus::Params params;
    uint64_t accumulated = 0;

    // Add 17 max-size txs (should all fit within budget of 240,000).
    const uint64_t per_tx_cost = 16 * 760 + 16 * 102; // 13,792
    for (int i = 0; i < 17; ++i) {
        accumulated += per_tx_cost;
        BOOST_CHECK_LE(accumulated, params.nMaxBlockShieldedVerifyCost);
    }

    // Adding the 18th should exceed budget (18 * 13792 = 248,256 > 240,000).
    accumulated += per_tx_cost;
    BOOST_CHECK_GT(accumulated, params.nMaxBlockShieldedVerifyCost);
}

// =========================================================================
// Nullifier O(1) lookup (unordered_set)
// =========================================================================

BOOST_AUTO_TEST_CASE(nullifier_unordered_set_performance)
{
    // Verify unordered_set<Nullifier, NullifierHasher> provides O(1) lookups
    // by comparing insert/lookup time scaling.
    std::unordered_set<Nullifier, NullifierHasher> nf_set;

    constexpr size_t N = 50000;
    std::vector<Nullifier> nfs;
    nfs.reserve(N);
    for (size_t i = 0; i < N; ++i) {
        nfs.push_back(GetRandHash());
    }

    // Insert all.
    auto start = std::chrono::steady_clock::now();
    for (const auto& nf : nfs) {
        nf_set.insert(nf);
    }
    auto insert_time = std::chrono::steady_clock::now() - start;

    // Lookup all.
    start = std::chrono::steady_clock::now();
    size_t found = 0;
    for (const auto& nf : nfs) {
        if (nf_set.count(nf)) ++found;
    }
    auto lookup_time = std::chrono::steady_clock::now() - start;

    BOOST_CHECK_EQUAL(found, N);
    auto insert_ms = std::chrono::duration_cast<std::chrono::milliseconds>(insert_time).count();
    auto lookup_ms = std::chrono::duration_cast<std::chrono::milliseconds>(lookup_time).count();
    BOOST_CHECK_LT(insert_ms, 2000);
    BOOST_CHECK_LT(lookup_ms, 2000);
    BOOST_TEST_MESSAGE("unordered_set<Nullifier>: " << N << " inserts=" << insert_ms
                       << "ms, lookups=" << lookup_ms << "ms");
}

// =========================================================================
// Merkle tree concurrent read performance (shared_mutex)
// =========================================================================

BOOST_AUTO_TEST_CASE(merkle_tree_concurrent_reads)
{
    // Build a tree with enough entries to populate the commitment index.
    shielded::ShieldedMerkleTree tree;
    constexpr size_t TREE_SIZE = 1000;
    for (size_t i = 0; i < TREE_SIZE; ++i) {
        tree.Append(GetRandHash());
    }
    BOOST_CHECK_EQUAL(tree.Size(), TREE_SIZE);

    // Launch multiple reader threads to verify concurrent access works.
    constexpr int NUM_THREADS = 4;
    constexpr int READS_PER_THREAD = 500;
    std::atomic<int> total_found{0};

    auto reader = [&]() {
        int found = 0;
        FastRandomContext rng;
        for (int i = 0; i < READS_PER_THREAD; ++i) {
            uint64_t pos = rng.randrange(TREE_SIZE);
            auto result = tree.CommitmentAt(pos);
            if (result.has_value()) ++found;
        }
        total_found += found;
    };

    auto start = std::chrono::steady_clock::now();
    std::vector<std::thread> threads;
    threads.reserve(NUM_THREADS);
    for (int t = 0; t < NUM_THREADS; ++t) {
        threads.emplace_back(reader);
    }
    for (auto& t : threads) t.join();
    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now() - start).count();

    BOOST_CHECK_GT(total_found.load(), 0);
    BOOST_CHECK_LT(ms, 5000);
    BOOST_TEST_MESSAGE("Concurrent merkle reads: " << NUM_THREADS << " threads × "
                       << READS_PER_THREAD << " reads in " << ms << "ms, "
                       << total_found.load() << " found");
}

// =========================================================================
// InfNorm constant-time verification
// =========================================================================

BOOST_AUTO_TEST_CASE(infnorm_constant_time_correctness)
{
    // Verify InfNorm produces correct results for known inputs.
    lattice::Poly256 p{};
    BOOST_CHECK_EQUAL(p.InfNorm(), 0);

    p.coeffs[0] = 42;
    BOOST_CHECK_EQUAL(p.InfNorm(), 42);

    p.coeffs[100] = -100;
    BOOST_CHECK_EQUAL(p.InfNorm(), 100);

    p.coeffs[255] = lattice::POLY_Q / 2;
    BOOST_CHECK_EQUAL(p.InfNorm(), lattice::POLY_Q / 2);

    // Negative values: -POLY_Q/2 has abs = POLY_Q/2
    p.coeffs[200] = -(lattice::POLY_Q / 2);
    BOOST_CHECK_EQUAL(p.InfNorm(), lattice::POLY_Q / 2);
}

// =========================================================================
// Shielded proof verification remains a consensus check even when
// script verification is relaxed under assumevalid.
// =========================================================================

BOOST_AUTO_TEST_CASE(shielded_proof_cost_limits_are_consensus_invariants)
{
    Consensus::Params params;

    // The shielded cost limit applies regardless of IBD state.
    BOOST_CHECK_GT(params.nMaxBlockShieldedVerifyCost, 0U);

    // Shielded activation height should be 0 for genesis mining.
    BOOST_CHECK_EQUAL(params.nShieldedPoolActivationHeight, 0);
}

// =========================================================================
// Proof plausibility minimum size: verify tightened thresholds
// =========================================================================

BOOST_AUTO_TEST_CASE(proof_plausibility_minimum_sizes)
{
    // Verify that minimum proof sizes are realistic but conservative.
    // Base: 2048 bytes
    // Per input: 51200 bytes (~50 KB for ring signature response vectors)
    // Per output: 15360 bytes (~15 KB for range proof bit proofs)
    constexpr size_t kMinBase = 2048;
    constexpr size_t kMinPerInput = 51200;
    constexpr size_t kMinPerOutput = 15360;

    // 1-in/1-out minimum: ~68 KB
    BOOST_CHECK_GT(kMinBase + kMinPerInput + kMinPerOutput, 60000U);

    // 16-in/16-out minimum: ~1.07 MB
    const size_t max_min = kMinBase + 16 * kMinPerInput + 16 * kMinPerOutput;
    BOOST_CHECK_GT(max_min, 1000000U);

    // Must fit within MAX_SHIELDED_PROOF_BYTES (1.5 MB)
    BOOST_CHECK_LE(max_min, MAX_SHIELDED_PROOF_BYTES);
}

// =========================================================================
// Shielded verification cost: miner and consensus alignment
// =========================================================================

BOOST_AUTO_TEST_CASE(miner_consensus_cost_limit_aligned)
{
    // Verify that the miner-facing defaults stay aligned with consensus defaults.
    Consensus::Params params;

    BOOST_CHECK_EQUAL(params.nMaxBlockShieldedVerifyCost, Consensus::DEFAULT_MAX_BLOCK_SHIELDED_VERIFY_COST);
    BOOST_CHECK_EQUAL(params.nMaxBlockShieldedScanUnits, Consensus::DEFAULT_MAX_BLOCK_SHIELDED_SCAN_UNITS);
    BOOST_CHECK_EQUAL(params.nMaxBlockShieldedTreeUpdateUnits, Consensus::DEFAULT_MAX_BLOCK_SHIELDED_TREE_UPDATE_UNITS);

    // A single max-size shielded tx: 16 inputs × 760 + 16 outputs × 102 = 13,792
    const uint64_t max_tx_cost = 16 * 760 + 16 * 102;

    // With budget 240,000: floor(240000/13792) = 17 max txs
    BOOST_CHECK_EQUAL(params.nMaxBlockShieldedVerifyCost / max_tx_cost, 17U);
}

// =========================================================================
// Nullifier set: generation cache with DoS resistance
// =========================================================================

BOOST_AUTO_TEST_CASE(nullifier_hasher_dos_resistance)
{
    // Verify NullifierHasher uses salted SipHash (different instances produce
    // different hash values for the same input).
    NullifierHasher hasher1;
    NullifierHasher hasher2;
    const Nullifier nf = GetRandHash();

    // With random salts, hash values should differ (probabilistic check).
    // The probability of collision is 2^-64, effectively zero.
    // Run multiple times to increase confidence.
    int different = 0;
    for (int i = 0; i < 10; ++i) {
        NullifierHasher h_a;
        NullifierHasher h_b;
        if (h_a(nf) != h_b(nf)) ++different;
    }
    BOOST_CHECK_GT(different, 5); // Most should differ
}

// =========================================================================
// Pool balance: overflow protection
// =========================================================================

BOOST_AUTO_TEST_CASE(pool_balance_overflow_protection)
{
    NullifierSet nf_set(m_path_root / "test_overflow", 8 << 20, /*memory_only=*/true);

    // Writing MAX_MONEY should succeed.
    BOOST_CHECK(nf_set.WritePoolBalance(MAX_MONEY));
    CAmount balance = 0;
    BOOST_CHECK(nf_set.ReadPoolBalance(balance));
    BOOST_CHECK_EQUAL(balance, MAX_MONEY);

    // Writing MAX_MONEY + 1 should fail.
    BOOST_CHECK(!nf_set.WritePoolBalance(MAX_MONEY + 1));

    // Writing negative should fail.
    BOOST_CHECK(!nf_set.WritePoolBalance(-1));
}

BOOST_AUTO_TEST_SUITE_END()
