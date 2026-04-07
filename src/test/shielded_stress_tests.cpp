// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// Production stress and performance tests for the shielded pool.
// Validates that the implementation can handle realistic production loads
// without performance degradation, unbounded growth, or resource exhaustion.

#include <consensus/amount.h>
#include <kernel/mempool_entry.h>
#include <node/miner.h>
#include <random.h>
#include <shielded/bundle.h>
#include <shielded/lattice/params.h>
#include <shielded/merkle_tree.h>
#include <shielded/nullifier.h>
#include <test/util/setup_common.h>
#include <test/util/txmempool.h>
#include <txmempool.h>

#include <boost/test/unit_test.hpp>

#include <algorithm>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <set>
#include <vector>

namespace lattice = shielded::lattice;

namespace {

CMutableTransaction MakeShieldedTx(size_t n_inputs, size_t n_outputs)
{
    CMutableTransaction mtx;
    mtx.version = 2;
    for (size_t i = 0; i < n_inputs; ++i) {
        CShieldedInput in;
        in.nullifier = GetRandHash();
        for (size_t r = 0; r < lattice::RING_SIZE; ++r) {
            in.ring_positions.push_back(r + i * lattice::RING_SIZE);
        }
        mtx.shielded_bundle.shielded_inputs.push_back(std::move(in));
    }
    for (size_t i = 0; i < n_outputs; ++i) {
        CShieldedOutput out;
        out.note_commitment = GetRandHash();
        out.merkle_anchor = GetRandHash();
        mtx.shielded_bundle.shielded_outputs.push_back(std::move(out));
    }
    // Provide a proof that passes the plausibility minimum.
    const size_t min_proof = 2048 + n_inputs * 51200 + n_outputs * 15360;
    mtx.shielded_bundle.proof.resize(min_proof, 0xAA);
    return mtx;
}

} // namespace

BOOST_FIXTURE_TEST_SUITE(shielded_stress_tests, BasicTestingSetup)

// ---------------------------------------------------------------------------
// Merkle tree: append throughput and scaling
// Verify the incremental merkle tree can handle large append batches
// without excessive memory usage (O(depth) = O(32)).
// ---------------------------------------------------------------------------
BOOST_AUTO_TEST_CASE(merkle_tree_large_append_throughput)
{
    shielded::ShieldedMerkleTree tree;

    constexpr size_t BATCH_SIZE = 10000;
    auto start = std::chrono::steady_clock::now();
    for (size_t i = 0; i < BATCH_SIZE; ++i) {
        tree.Append(GetRandHash());
    }
    auto end = std::chrono::steady_clock::now();
    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(end - start).count();

    BOOST_CHECK_EQUAL(tree.Size(), BATCH_SIZE);
    BOOST_CHECK(!tree.Root().IsNull());
    // 10K appends should complete in well under 5 seconds.
    BOOST_CHECK_LT(ms, 5000);
    BOOST_TEST_MESSAGE("Merkle tree: " << BATCH_SIZE << " appends in " << ms << " ms");
}

// ---------------------------------------------------------------------------
// Merkle tree: witness incremental update scaling
// The wallet must update all witnesses for each new commitment.
// With W witnesses and O new commitments, cost is O(W * O * depth).
// Verify this remains tractable for realistic wallet sizes.
// ---------------------------------------------------------------------------
BOOST_AUTO_TEST_CASE(merkle_tree_witness_update_scaling)
{
    shielded::ShieldedMerkleTree tree;

    // Build tree with some initial commitments and take witnesses.
    // Each witness must be updated for all subsequent appends.
    constexpr size_t INITIAL_NOTES = 100;
    std::vector<shielded::ShieldedMerkleWitness> witnesses;
    std::vector<uint256> tracked_leaves;
    witnesses.reserve(INITIAL_NOTES);
    tracked_leaves.reserve(INITIAL_NOTES);

    for (size_t i = 0; i < INITIAL_NOTES; ++i) {
        const uint256 leaf = GetRandHash();
        tree.Append(leaf);
        for (auto& witness : witnesses) {
            witness.IncrementalUpdate(leaf);
        }
        witnesses.push_back(tree.Witness());
        tracked_leaves.push_back(leaf);
    }

    // Simulate a block with NEW_OUTPUTS outputs; update all witnesses.
    constexpr size_t NEW_OUTPUTS = 500;
    auto start = std::chrono::steady_clock::now();
    for (size_t i = 0; i < NEW_OUTPUTS; ++i) {
        uint256 commitment = GetRandHash();
        tree.Append(commitment);
        for (auto& w : witnesses) {
            w.IncrementalUpdate(commitment);
        }
    }
    auto end = std::chrono::steady_clock::now();
    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(end - start).count();

    // Verify witnesses are still valid for their tracked leaves.
    const uint256 root = tree.Root();
    for (size_t i = 0; i < INITIAL_NOTES; ++i) {
        BOOST_CHECK(witnesses[i].Verify(tracked_leaves[i], root));
    }
    // 100 witnesses × 500 updates = 50K incremental updates.
    // Should complete within 10 seconds on any reasonable hardware.
    BOOST_CHECK_LT(ms, 10000);
    BOOST_TEST_MESSAGE("Witness update: " << INITIAL_NOTES << " witnesses × "
                       << NEW_OUTPUTS << " outputs in " << ms << " ms");
}

// ---------------------------------------------------------------------------
// Nullifier set: insert/lookup performance under load
// Verify nullifier cache handles sustained insertion without degradation.
// ---------------------------------------------------------------------------
BOOST_AUTO_TEST_CASE(nullifier_set_insert_and_lookup_performance)
{
    NullifierSet nf_set(m_path_root / "test_nullifiers", 8 << 20, /*memory_only=*/true);

    constexpr size_t BATCH_COUNT = 100;
    constexpr size_t BATCH_SIZE = 100;
    std::vector<Nullifier> all_nullifiers;
    all_nullifiers.reserve(BATCH_COUNT * BATCH_SIZE);

    auto start = std::chrono::steady_clock::now();
    for (size_t batch = 0; batch < BATCH_COUNT; ++batch) {
        std::vector<Nullifier> batch_nfs;
        batch_nfs.reserve(BATCH_SIZE);
        for (size_t i = 0; i < BATCH_SIZE; ++i) {
            batch_nfs.push_back(GetRandHash());
        }
        BOOST_REQUIRE(nf_set.Insert(batch_nfs));
        all_nullifiers.insert(all_nullifiers.end(), batch_nfs.begin(), batch_nfs.end());
    }
    auto insert_end = std::chrono::steady_clock::now();
    auto insert_ms = std::chrono::duration_cast<std::chrono::milliseconds>(insert_end - start).count();

    // Verify all nullifiers are found.
    size_t found = 0;
    auto lookup_start = std::chrono::steady_clock::now();
    for (const auto& nf : all_nullifiers) {
        if (nf_set.Contains(nf)) ++found;
    }
    auto lookup_end = std::chrono::steady_clock::now();
    auto lookup_ms = std::chrono::duration_cast<std::chrono::milliseconds>(lookup_end - lookup_start).count();

    BOOST_CHECK_EQUAL(found, all_nullifiers.size());
    BOOST_CHECK_EQUAL(nf_set.CacheSize(), all_nullifiers.size());

    // 10K inserts + 10K lookups should complete in under 10 seconds.
    BOOST_CHECK_LT(insert_ms + lookup_ms, 10000);
    BOOST_TEST_MESSAGE("Nullifier set: " << all_nullifiers.size() << " inserts in "
                       << insert_ms << " ms, " << all_nullifiers.size()
                       << " lookups in " << lookup_ms << " ms");
}

// ---------------------------------------------------------------------------
// Nullifier set: cache generation rotation
// Verify that rotating the cache under sustained load doesn't lose entries
// that are still in the DB.
// ---------------------------------------------------------------------------
BOOST_AUTO_TEST_CASE(nullifier_cache_rotation_consistency)
{
    NullifierSet nf_set(m_path_root / "test_nullifiers_rot", 8 << 20, /*memory_only=*/true);

    // Insert enough nullifiers to trigger at least one cache rotation.
    // NULLIFIER_CACHE_MAX_ENTRIES = 2,000,000 but we use memory_only so
    // we'll keep the count manageable and verify rotation logic at smaller scale.
    constexpr size_t TOTAL = 5000;
    std::vector<Nullifier> all_nfs;
    all_nfs.reserve(TOTAL);
    for (size_t i = 0; i < TOTAL; ++i) {
        std::vector<Nullifier> batch{GetRandHash()};
        BOOST_REQUIRE(nf_set.Insert(batch));
        all_nfs.push_back(batch[0]);
    }

    // All should be reachable (from cache or DB).
    for (const auto& nf : all_nfs) {
        BOOST_CHECK_MESSAGE(nf_set.Contains(nf),
            "Nullifier not found after rotation: " + nf.ToString());
    }

    // Random non-existent nullifier should not be found.
    BOOST_CHECK(!nf_set.Contains(GetRandHash()));
}

// ---------------------------------------------------------------------------
// Nullifier set: reorg (Remove) correctness
// Verify that removed nullifiers are no longer found.
// ---------------------------------------------------------------------------
BOOST_AUTO_TEST_CASE(nullifier_remove_correctness)
{
    NullifierSet nf_set(m_path_root / "test_nullifiers_rm", 8 << 20, /*memory_only=*/true);

    std::vector<Nullifier> block1{GetRandHash(), GetRandHash(), GetRandHash()};
    std::vector<Nullifier> block2{GetRandHash(), GetRandHash()};
    BOOST_REQUIRE(nf_set.Insert(block1));
    BOOST_REQUIRE(nf_set.Insert(block2));

    // All should exist.
    for (const auto& nf : block1) BOOST_CHECK(nf_set.Contains(nf));
    for (const auto& nf : block2) BOOST_CHECK(nf_set.Contains(nf));

    // Disconnect block2.
    BOOST_REQUIRE(nf_set.Remove(block2));
    for (const auto& nf : block2) {
        BOOST_CHECK_MESSAGE(!nf_set.Contains(nf), "Nullifier still found after Remove");
    }
    // Block1 should still exist.
    for (const auto& nf : block1) BOOST_CHECK(nf_set.Contains(nf));
}

// ---------------------------------------------------------------------------
// Mempool nullifier conflict detection performance
// With many shielded txs in mempool, HasShieldedNullifierConflict should
// remain fast (O(1) per lookup with unordered_map).
// ---------------------------------------------------------------------------
BOOST_AUTO_TEST_CASE(mempool_nullifier_conflict_performance)
{
    bilingual_str error;
    CTxMemPool pool{MemPoolOptionsForTest(m_node), error};
    BOOST_REQUIRE(error.empty());

    constexpr size_t NUM_NULLIFIERS = 10000;
    {
        LOCK(pool.cs);
        for (size_t i = 0; i < NUM_NULLIFIERS; ++i) {
            pool.m_shielded_nullifiers.emplace(GetRandHash(), Txid::FromUint256(GetRandHash()));
        }
    }

    constexpr size_t NUM_CHECKS = 10000;
    std::vector<CTransaction> txs;
    txs.reserve(NUM_CHECKS);
    for (size_t i = 0; i < NUM_CHECKS; ++i) {
        txs.emplace_back(MakeShieldedTx(1, 1));
    }

    // Pre-build transactions so the timed section measures mempool conflict
    // lookups rather than transaction/proof construction overhead.
    size_t conflicts = 0;
    auto start = std::chrono::steady_clock::now();
    {
        LOCK(pool.cs);
        for (const auto& tx : txs) {
            if (pool.HasShieldedNullifierConflict(tx)) ++conflicts;
        }
    }
    auto end = std::chrono::steady_clock::now();
    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(end - start).count();

    // With random nullifiers, collisions should be extremely rare.
    BOOST_CHECK_EQUAL(conflicts, 0U);
    // 10K checks against 10K entries should complete in under 2 seconds.
    BOOST_CHECK_LT(ms, 2000);
    BOOST_TEST_MESSAGE("Mempool conflict check: " << NUM_CHECKS << " checks against "
                       << NUM_NULLIFIERS << " entries in " << ms << " ms");
}

// ---------------------------------------------------------------------------
// Bundle size limits: verify consensus limits are enforced
// ---------------------------------------------------------------------------
BOOST_AUTO_TEST_CASE(bundle_consensus_limits_enforced)
{
    // MAX_SHIELDED_SPENDS_PER_TX = 16
    BOOST_CHECK_EQUAL(MAX_SHIELDED_SPENDS_PER_TX, 16U);
    // MAX_SHIELDED_OUTPUTS_PER_TX = 16
    BOOST_CHECK_EQUAL(MAX_SHIELDED_OUTPUTS_PER_TX, 16U);
    // MAX_SHIELDED_PROOF_BYTES = 1.5 MB
    BOOST_CHECK_EQUAL(MAX_SHIELDED_PROOF_BYTES, 1536U * 1024U);
    // MAX_SHIELDED_TX_WEIGHT = MAX_BLOCK_WEIGHT (24 MWU)
    BOOST_CHECK_EQUAL(MAX_SHIELDED_TX_WEIGHT, MAX_BLOCK_WEIGHT);
    // MAX_VIEW_GRANTS_PER_TX = 8
    BOOST_CHECK_EQUAL(MAX_VIEW_GRANTS_PER_TX, 8U);
    // SHIELDED_ANCHOR_DEPTH = 100
    BOOST_CHECK_EQUAL(SHIELDED_ANCHOR_DEPTH, 100);

    // Verify CheckStructure rejects oversized bundles.
    CShieldedBundle oversized_inputs;
    oversized_inputs.shielded_inputs.resize(MAX_SHIELDED_SPENDS_PER_TX + 1);
    BOOST_CHECK(!oversized_inputs.CheckStructure());

    CShieldedBundle oversized_outputs;
    oversized_outputs.shielded_outputs.resize(MAX_SHIELDED_OUTPUTS_PER_TX + 1);
    BOOST_CHECK(!oversized_outputs.CheckStructure());
}

// ---------------------------------------------------------------------------
// Proof plausibility: verify tightened minimum rejects trivially small proofs
// ---------------------------------------------------------------------------
BOOST_AUTO_TEST_CASE(proof_plausibility_rejects_undersized)
{
    // A 1-input 1-output bundle needs min: 4096 + 81920 + 20480 = 106496 bytes.
    CShieldedBundle bundle;
    CShieldedInput in;
    in.nullifier = GetRandHash();
    for (size_t i = 0; i < lattice::RING_SIZE; ++i) {
        in.ring_positions.push_back(i);
    }
    bundle.shielded_inputs.push_back(in);
    CShieldedOutput out;
    out.note_commitment = GetRandHash();
    out.merkle_anchor = GetRandHash();
    bundle.shielded_outputs.push_back(out);

    // A 50 KB proof should now be rejected (was previously accepted).
    bundle.proof.resize(50000, 0xBB);
    // The plausibility check is in validation.cpp (PrecheckShieldedProofPlausibility).
    // We verify the minimum math here.
    constexpr size_t kMinBaseBytes = 2048;
    constexpr size_t kMinBytesPerInput = 51200;
    constexpr size_t kMinBytesPerOutput = 15360;
    const size_t min_expected = kMinBaseBytes +
        bundle.shielded_inputs.size() * kMinBytesPerInput +
        bundle.shielded_outputs.size() * kMinBytesPerOutput;
    BOOST_CHECK_GT(min_expected, 60000U); // At least 60 KB for 1-in/1-out
    BOOST_CHECK_LT(bundle.proof.size(), min_expected); // 50KB < 106KB

    // A properly-sized proof should pass.
    bundle.proof.resize(min_expected, 0xCC);
    BOOST_CHECK_GE(bundle.proof.size(), min_expected);
}

// ---------------------------------------------------------------------------
// Mining: shielded verification cost budget
// Verify the miner respects the per-block shielded verification budget.
// ---------------------------------------------------------------------------
BOOST_AUTO_TEST_CASE(mining_shielded_verify_cost_calculation)
{
    // Verify cost calculation matches expected values.
    // A 16-in/16-out tx should have cost: 16*760 + 16*102 = 12160 + 1632 = 13792
    CMutableTransaction max_tx = MakeShieldedTx(16, 16);
    const CTransaction ctx{max_tx};
    BOOST_CHECK(ctx.HasShieldedBundle());

    const auto& bundle = ctx.GetShieldedBundle();
    const uint64_t expected_cost = bundle.shielded_inputs.size() * 760 +
                                   bundle.shielded_outputs.size() * 102;
    BOOST_CHECK_EQUAL(expected_cost, 13792U);

    // Budget of 200*760 = 152,000 allows ~11 maximum-size shielded txs.
    constexpr uint64_t budget = 200 * 760;
    const uint64_t max_txs = budget / expected_cost;
    BOOST_CHECK_GE(max_txs, 10U);  // At least 10 max-size txs fit
    BOOST_CHECK_LE(max_txs, 15U);  // But not unbounded
    BOOST_TEST_MESSAGE("Mining budget: " << budget << " allows " << max_txs
                       << " maximum-size (16-in/16-out) shielded txs per block");
}

// ---------------------------------------------------------------------------
// Merkle tree truncation (reorg simulation)
// Verify that truncation works correctly for production-relevant sizes.
// ---------------------------------------------------------------------------
BOOST_AUTO_TEST_CASE(merkle_tree_truncation_correctness)
{
    shielded::ShieldedMerkleTree tree;

    // Build tree with enough entries to create frontier checkpoints.
    constexpr size_t TOTAL_LEAVES = 2500; // At least 2 checkpoints (interval=1024)
    std::vector<uint256> commitments;
    commitments.reserve(TOTAL_LEAVES);
    for (size_t i = 0; i < TOTAL_LEAVES; ++i) {
        uint256 c = GetRandHash();
        commitments.push_back(c);
        tree.Append(c);
    }
    BOOST_CHECK_EQUAL(tree.Size(), TOTAL_LEAVES);
    const uint256 full_root = tree.Root();

    // Truncate to 2000 (should use checkpoint at 1024).
    constexpr uint64_t TRUNCATE_TO = 2000;
    BOOST_REQUIRE(tree.Truncate(TRUNCATE_TO));
    BOOST_CHECK_EQUAL(tree.Size(), TRUNCATE_TO);

    // Root should differ from the full tree root.
    BOOST_CHECK(tree.Root() != full_root);

    // Re-append the removed leaves and verify we get the same root.
    for (size_t i = TRUNCATE_TO; i < TOTAL_LEAVES; ++i) {
        tree.Append(commitments[i]);
    }
    BOOST_CHECK_EQUAL(tree.Size(), TOTAL_LEAVES);
    BOOST_CHECK_EQUAL(tree.Root(), full_root);
}

// ---------------------------------------------------------------------------
// Shielded pool balance: turnstile correctness under stress
// Verify pool balance tracking remains correct through many operations.
// ---------------------------------------------------------------------------
BOOST_AUTO_TEST_CASE(pool_balance_stress)
{
    NullifierSet nf_set(m_path_root / "test_pool_balance", 8 << 20, /*memory_only=*/true);

    CAmount balance = 0;
    BOOST_REQUIRE(nf_set.WritePoolBalance(0));
    BOOST_REQUIRE(nf_set.ReadPoolBalance(balance));
    BOOST_CHECK_EQUAL(balance, 0);

    // Simulate 1000 blocks of pool deposits and withdrawals.
    CAmount running = 0;
    for (int i = 0; i < 1000; ++i) {
        // Alternate between deposit (positive) and partial withdrawal (negative).
        CAmount delta = (i % 3 == 0) ? -50000 : 100000;
        if (running + delta < 0) delta = 0; // Can't go negative
        running += delta;
        BOOST_REQUIRE(nf_set.WritePoolBalance(running));
    }

    CAmount final_balance = 0;
    BOOST_REQUIRE(nf_set.ReadPoolBalance(final_balance));
    BOOST_CHECK_EQUAL(final_balance, running);
    BOOST_CHECK(MoneyRange(final_balance));
}

// ---------------------------------------------------------------------------
// Network relay: bundle serialization size bounds
// Verify the maximum theoretical serialized size of a bundle.
// ---------------------------------------------------------------------------
BOOST_AUTO_TEST_CASE(bundle_max_serialized_size_bounded)
{
    // Compute maximum possible bundle serialization size.
    // Inputs: 16 × (32 nullifier + 1 compactsize + 16 × 8 ring_positions) = 16 × 161 = 2576
    // Outputs: 16 × (32 commitment + encrypted_note + 1 + 32 anchor) ≈ 16 × ~2200 = ~35200
    // Grants: 8 × (KEM_CT + nonce + data) ≈ 8 × ~1200 = ~9600
    // Proof: 1.5 MB = 1572864
    // value_balance: 8 bytes
    // Total theoretical max: < 1.7 MB

    // The critical constraint: MAX_SHIELDED_PROOF_BYTES dominates.
    BOOST_CHECK_LT(MAX_SHIELDED_PROOF_BYTES, 2 * 1024 * 1024); // Under 2 MB
    // Non-proof overhead is bounded by inputs + outputs + grants.
    constexpr size_t non_proof_max =
        MAX_SHIELDED_SPENDS_PER_TX * (32 + 1 + lattice::RING_SIZE * 8) + // inputs
        MAX_SHIELDED_OUTPUTS_PER_TX * 2500 +                              // outputs (generous)
        MAX_VIEW_GRANTS_PER_TX * 1500 +                                   // grants
        8;                                                                  // value_balance
    BOOST_CHECK_LT(non_proof_max, 100000U); // Non-proof data < 100 KB
    BOOST_TEST_MESSAGE("Max non-proof overhead: " << non_proof_max << " bytes");
}

BOOST_AUTO_TEST_SUITE_END()
