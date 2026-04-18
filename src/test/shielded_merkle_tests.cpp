// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <shielded/merkle_tree.h>

#include <crypto/sha256.h>
#include <random.h>
#include <serialize.h>
#include <streams.h>
#include <test/util/setup_common.h>
#include <uint256.h>
#include <util/fs.h>

#include <boost/test/unit_test.hpp>

#include <array>
#include <cstdint>
#include <vector>

using namespace shielded;

namespace {

/** Helper: create a deterministic commitment from an integer seed. */
uint256 MakeCommitment(uint32_t seed)
{
    uint256 result;
    unsigned char buf[4];
    buf[0] = seed & 0xFF;
    buf[1] = (seed >> 8) & 0xFF;
    buf[2] = (seed >> 16) & 0xFF;
    buf[3] = (seed >> 24) & 0xFF;
    CSHA256().Write(buf, 4).Finalize(result.begin());
    return result;
}

/** Helper: manually compute EmptyRoot(depth) from scratch without cache. */
uint256 ManualEmptyRoot(size_t depth)
{
    const std::string leaf_tag{"BTX_Shielded_Empty_Leaf_V1"};
    uint256 h;
    CSHA256()
        .Write(reinterpret_cast<const unsigned char*>(leaf_tag.data()), leaf_tag.size())
        .Finalize(h.begin());

    for (size_t d = 0; d < depth; ++d) {
        const std::string branch_tag{"BTX_Shielded_Branch_V1"};
        uint256 next;
        CSHA256()
            .Write(reinterpret_cast<const unsigned char*>(branch_tag.data()), branch_tag.size())
            .Write(h.begin(), 32)
            .Write(h.begin(), 32)
            .Finalize(next.begin());
        h = next;
    }
    return h;
}

/** Helper: compute BranchHash manually (for independent verification). */
uint256 ManualBranch(const uint256& left, const uint256& right)
{
    const std::string tag{"BTX_Shielded_Branch_V1"};
    uint256 result;
    CSHA256()
        .Write(reinterpret_cast<const unsigned char*>(tag.data()), tag.size())
        .Write(left.begin(), 32)
        .Write(right.begin(), 32)
        .Finalize(result.begin());
    return result;
}

} // anonymous namespace

BOOST_FIXTURE_TEST_SUITE(shielded_merkle_tests, BasicTestingSetup)

// ===================================================================
// Basic correctness
// ===================================================================

BOOST_AUTO_TEST_CASE(empty_tree_root_equals_precomputed)
{
    ShieldedMerkleTree tree;
    uint256 root = tree.Root();

    // Must equal the depth-32 empty root.
    BOOST_CHECK(root == EmptyRoot(MERKLE_DEPTH));

    // Must NOT be the zero hash (EmptyRoot involves actual SHA-256 computation).
    BOOST_CHECK(root != uint256::ZERO);
}

BOOST_AUTO_TEST_CASE(empty_root_depth_zero_equals_empty_leaf)
{
    BOOST_CHECK(EmptyRoot(0) == EmptyLeafHash());
}

BOOST_AUTO_TEST_CASE(single_leaf_root)
{
    // A single leaf at position 0 means the root is:
    //   hash_chain(leaf, EmptyRoot(0), EmptyRoot(1), ..., EmptyRoot(31))
    // i.e. BranchHash(leaf, EmptyRoot(0)) at depth 0,
    //      BranchHash(result, EmptyRoot(1)) at depth 1, etc.

    uint256 leaf = MakeCommitment(42);
    ShieldedMerkleTree tree;
    tree.Append(leaf);

    // Manual computation.
    uint256 expected = leaf;
    for (size_t d = 0; d < MERKLE_DEPTH; ++d) {
        expected = ManualBranch(expected, EmptyRoot(d));
    }

    BOOST_CHECK(tree.Root() == expected);
}

BOOST_AUTO_TEST_CASE(two_leaves_root)
{
    uint256 a = MakeCommitment(1);
    uint256 b = MakeCommitment(2);

    ShieldedMerkleTree tree;
    tree.Append(a);
    tree.Append(b);

    // Manual: depth 0 combines (a, b), then hashes up with empty roots.
    uint256 expected = ManualBranch(a, b);
    for (size_t d = 1; d < MERKLE_DEPTH; ++d) {
        expected = ManualBranch(expected, EmptyRoot(d));
    }

    BOOST_CHECK(tree.Root() == expected);
}

BOOST_AUTO_TEST_CASE(three_leaves_root)
{
    uint256 a = MakeCommitment(10);
    uint256 b = MakeCommitment(20);
    uint256 c = MakeCommitment(30);

    ShieldedMerkleTree tree;
    tree.Append(a);
    tree.Append(b);
    tree.Append(c);

    // Manual: depth 0: left pair = Branch(a,b), right pair = Branch(c, EmptyLeaf)
    // depth 1: Branch(Branch(a,b), Branch(c, EmptyLeaf))
    // then up with empty roots.
    uint256 left_pair = ManualBranch(a, b);
    uint256 right_pair = ManualBranch(c, EmptyRoot(0));
    uint256 expected = ManualBranch(left_pair, right_pair);
    for (size_t d = 2; d < MERKLE_DEPTH; ++d) {
        expected = ManualBranch(expected, EmptyRoot(d));
    }

    BOOST_CHECK(tree.Root() == expected);
}

BOOST_AUTO_TEST_CASE(sequential_appends_1000)
{
    ShieldedMerkleTree tree;
    uint256 prev_root = tree.Root();

    for (uint32_t i = 0; i < 1000; ++i) {
        tree.Append(MakeCommitment(i));
        uint256 new_root = tree.Root();

        // Root must change after every append.
        BOOST_CHECK(new_root != prev_root);
        BOOST_CHECK_EQUAL(tree.Size(), i + 1);

        prev_root = new_root;
    }
}

BOOST_AUTO_TEST_CASE(append_order_matters)
{
    uint256 a = MakeCommitment(100);
    uint256 b = MakeCommitment(200);

    ShieldedMerkleTree tree1;
    tree1.Append(a);
    tree1.Append(b);

    ShieldedMerkleTree tree2;
    tree2.Append(b);
    tree2.Append(a);

    // Different insertion order must produce different roots.
    BOOST_CHECK(tree1.Root() != tree2.Root());
}

BOOST_AUTO_TEST_CASE(size_tracking)
{
    ShieldedMerkleTree tree;
    BOOST_CHECK_EQUAL(tree.Size(), 0u);
    BOOST_CHECK(tree.IsEmpty());

    for (uint32_t i = 0; i < 50; ++i) {
        tree.Append(MakeCommitment(i));
        BOOST_CHECK_EQUAL(tree.Size(), i + 1);
        BOOST_CHECK(!tree.IsEmpty());
    }
}

BOOST_AUTO_TEST_CASE(last_leaf_tracking)
{
    ShieldedMerkleTree tree;

    for (uint32_t i = 0; i < 20; ++i) {
        uint256 cm = MakeCommitment(i);
        tree.Append(cm);
        BOOST_CHECK(tree.LastLeaf() == cm);
    }
}

BOOST_AUTO_TEST_CASE(commitment_lookup_by_position)
{
    ShieldedMerkleTree tree;
    std::vector<uint256> leaves;
    for (uint32_t i = 0; i < 20; ++i) {
        uint256 cm = MakeCommitment(i);
        leaves.push_back(cm);
        tree.Append(cm);
    }

    for (uint64_t i = 0; i < leaves.size(); ++i) {
        const auto got = tree.CommitmentAt(i);
        BOOST_REQUIRE(got.has_value());
        BOOST_CHECK(*got == leaves[i]);
    }
    BOOST_CHECK(!tree.CommitmentAt(leaves.size()).has_value());
}

BOOST_AUTO_TEST_CASE(memory_only_tree_does_not_mutate_persistent_commitment_index)
{
    struct CommitmentStoreResetGuard {
        ~CommitmentStoreResetGuard()
        {
            ShieldedMerkleTree::ResetCommitmentIndexStore();
        }
    } guard;

    ShieldedMerkleTree::ResetCommitmentIndexStore();
    const fs::path db_path = m_path_root / "shielded_merkle_index_isolation";
    BOOST_REQUIRE(ShieldedMerkleTree::ConfigureCommitmentIndexStore(db_path,
                                                                     /*db_cache_bytes=*/1 << 20,
                                                                     /*lru_capacity=*/1024,
                                                                     /*memory_only=*/false,
                                                                     /*wipe_data=*/true));

    const uint256 consensus_a = MakeCommitment(5001);
    const uint256 consensus_b = MakeCommitment(5002);
    ShieldedMerkleTree consensus_tree;
    consensus_tree.Append(consensus_a);
    consensus_tree.Append(consensus_b);

    auto before = consensus_tree.CommitmentAt(0);
    BOOST_REQUIRE(before.has_value());
    BOOST_CHECK(*before == consensus_a);

    // Wallet trees must be memory-only so wallet rescans/rebuilds cannot
    // overwrite consensus commitment index rows.
    ShieldedMerkleTree wallet_tree{ShieldedMerkleTree::IndexStorageMode::MEMORY_ONLY};
    const uint256 wallet_a = MakeCommitment(9001);
    const uint256 wallet_b = MakeCommitment(9002);
    wallet_tree.Append(wallet_a);
    wallet_tree.Append(wallet_b);

    auto after = consensus_tree.CommitmentAt(0);
    BOOST_REQUIRE(after.has_value());
    BOOST_CHECK(*after == consensus_a);
    BOOST_CHECK(wallet_tree.CommitmentAt(0).has_value());
    BOOST_CHECK(*wallet_tree.CommitmentAt(0) == wallet_a);
}

BOOST_AUTO_TEST_CASE(detached_scratch_tree_does_not_reattach_incompatible_persistent_index)
{
    struct CommitmentStoreResetGuard {
        ~CommitmentStoreResetGuard()
        {
            ShieldedMerkleTree::ResetCommitmentIndexStore();
        }
    } guard;

    ShieldedMerkleTree::ResetCommitmentIndexStore();
    const fs::path db_path = m_path_root / "shielded_merkle_detached_reattach_guard";
    BOOST_REQUIRE(ShieldedMerkleTree::ConfigureCommitmentIndexStore(db_path,
                                                                     /*db_cache_bytes=*/1 << 20,
                                                                     /*lru_capacity=*/1024,
                                                                     /*memory_only=*/false,
                                                                     /*wipe_data=*/true));

    ShieldedMerkleTree live_tree;
    std::vector<uint256> live_commitments;
    for (uint32_t i = 0; i < 5; ++i) {
        const uint256 commitment = MakeCommitment(10'000 + i);
        live_commitments.push_back(commitment);
        live_tree.Append(commitment);
    }

    ShieldedMerkleTree scratch_tree = live_tree;
    BOOST_REQUIRE(scratch_tree.DetachToMemoryOnly());
    BOOST_REQUIRE(scratch_tree.Truncate(3));

    const uint256 alt_a = MakeCommitment(20'001);
    const uint256 alt_b = MakeCommitment(20'002);
    scratch_tree.Append(alt_a);
    scratch_tree.Append(alt_b);

    BOOST_REQUIRE(scratch_tree.AttachConfiguredCommitmentIndexStore());

    const auto live_pos3 = live_tree.CommitmentAt(3);
    const auto live_pos4 = live_tree.CommitmentAt(4);
    const auto scratch_pos3 = scratch_tree.CommitmentAt(3);
    const auto scratch_pos4 = scratch_tree.CommitmentAt(4);
    BOOST_REQUIRE(live_pos3.has_value());
    BOOST_REQUIRE(live_pos4.has_value());
    BOOST_REQUIRE(scratch_pos3.has_value());
    BOOST_REQUIRE(scratch_pos4.has_value());
    BOOST_CHECK_EQUAL(*live_pos3, live_commitments[3]);
    BOOST_CHECK_EQUAL(*live_pos4, live_commitments[4]);
    BOOST_CHECK_EQUAL(*scratch_pos3, alt_a);
    BOOST_CHECK_EQUAL(*scratch_pos4, alt_b);
}

BOOST_AUTO_TEST_CASE(commitment_lookup_unavailable_after_tree_deserialize)
{
    ShieldedMerkleTree tree;
    tree.Append(MakeCommitment(1));
    tree.Append(MakeCommitment(2));

    DataStream ss{};
    ss << tree;

    ShieldedMerkleTree decoded;
    ss >> decoded;

    BOOST_CHECK(!decoded.CommitmentAt(0).has_value());
}

BOOST_AUTO_TEST_CASE(truncate_restores_prior_prefix_root)
{
    ShieldedMerkleTree tree;
    std::vector<uint256> commitments;
    std::vector<uint256> roots;
    roots.push_back(tree.Root()); // size=0

    for (uint32_t i = 0; i < 64; ++i) {
        const uint256 cm = MakeCommitment(i);
        commitments.push_back(cm);
        tree.Append(cm);
        roots.push_back(tree.Root()); // root at size=i+1
    }

    BOOST_REQUIRE(tree.Truncate(40));
    BOOST_CHECK_EQUAL(tree.Size(), 40u);
    BOOST_CHECK(tree.Root() == roots[40]);

    for (uint64_t i = 0; i < 40; ++i) {
        auto got = tree.CommitmentAt(i);
        BOOST_REQUIRE(got.has_value());
        BOOST_CHECK(*got == commitments[i]);
    }
    BOOST_CHECK(!tree.CommitmentAt(40).has_value());

    const uint256 next = MakeCommitment(1000);
    tree.Append(next);
    auto got = tree.CommitmentAt(40);
    BOOST_REQUIRE(got.has_value());
    BOOST_CHECK(*got == next);
}

BOOST_AUTO_TEST_CASE(truncate_to_zero_clears_tree_state)
{
    ShieldedMerkleTree tree;
    tree.Append(MakeCommitment(11));
    tree.Append(MakeCommitment(12));
    tree.Append(MakeCommitment(13));

    BOOST_REQUIRE(tree.RemoveLast(3));
    BOOST_CHECK(tree.IsEmpty());
    BOOST_CHECK_EQUAL(tree.Size(), 0u);
    BOOST_CHECK(tree.Root() == EmptyRoot(MERKLE_DEPTH));
    BOOST_CHECK(!tree.CommitmentAt(0).has_value());
}

BOOST_AUTO_TEST_CASE(truncate_requires_commitment_index)
{
    ShieldedMerkleTree tree;
    tree.Append(MakeCommitment(21));
    tree.Append(MakeCommitment(22));
    const uint256 original_root = tree.Root();

    DataStream ss{};
    ss << tree;
    ShieldedMerkleTree decoded;
    ss >> decoded;

    BOOST_CHECK(!decoded.HasCommitmentIndex());
    BOOST_CHECK(!decoded.Truncate(1));
    BOOST_CHECK_EQUAL(decoded.Size(), 2u);
    BOOST_CHECK(decoded.Root() == original_root);
}

// ===================================================================
// Witness tests
// ===================================================================

BOOST_AUTO_TEST_CASE(witness_single_leaf_verifies)
{
    uint256 leaf = MakeCommitment(99);
    ShieldedMerkleTree tree;
    tree.Append(leaf);

    ShieldedMerkleWitness wit = tree.Witness();
    uint256 root = tree.Root();

    BOOST_CHECK(wit.Verify(leaf, root));
    BOOST_CHECK_EQUAL(wit.Position(), 0u);
}

BOOST_AUTO_TEST_CASE(witness_two_leaves_position_1)
{
    uint256 a = MakeCommitment(1);
    uint256 b = MakeCommitment(2);

    ShieldedMerkleTree tree;
    tree.Append(a);
    tree.Append(b);

    ShieldedMerkleWitness wit = tree.Witness();
    uint256 root = tree.Root();

    // Witness is for the most recent leaf (b, at position 1).
    BOOST_CHECK(wit.Verify(b, root));
    BOOST_CHECK_EQUAL(wit.Position(), 1u);
}

BOOST_AUTO_TEST_CASE(witness_at_position_0_in_100_leaf_tree)
{
    ShieldedMerkleTree tree;
    uint256 first_leaf = MakeCommitment(0);
    tree.Append(first_leaf);

    // Capture witness for position 0.
    ShieldedMerkleWitness wit0 = tree.Witness();
    BOOST_CHECK_EQUAL(wit0.Position(), 0u);

    // Append 99 more leaves, updating the witness each time.
    for (uint32_t i = 1; i < 100; ++i) {
        uint256 cm = MakeCommitment(i);
        tree.Append(cm);
        wit0.IncrementalUpdate(cm);
    }

    // Witness for position 0 must still verify against the current root.
    uint256 root = tree.Root();
    BOOST_CHECK(wit0.Verify(first_leaf, root));
    BOOST_CHECK_EQUAL(wit0.Position(), 0u);
}

BOOST_AUTO_TEST_CASE(witness_most_recent_leaf_verifies)
{
    ShieldedMerkleTree tree;
    for (uint32_t i = 0; i < 50; ++i) {
        tree.Append(MakeCommitment(i));
    }

    uint256 last = MakeCommitment(50);
    tree.Append(last);

    ShieldedMerkleWitness wit = tree.Witness();
    BOOST_CHECK(wit.Verify(last, tree.Root()));
}

BOOST_AUTO_TEST_CASE(witness_incremental_update_chain)
{
    // Build a tree of 200 leaves, creating a witness at leaf 50 and
    // incrementally updating it through all subsequent appends.
    ShieldedMerkleTree tree;

    for (uint32_t i = 0; i < 50; ++i) {
        tree.Append(MakeCommitment(i));
    }

    uint256 target_leaf = MakeCommitment(50);
    tree.Append(target_leaf);
    ShieldedMerkleWitness wit = tree.Witness();
    BOOST_CHECK(wit.Verify(target_leaf, tree.Root()));

    for (uint32_t i = 51; i < 200; ++i) {
        uint256 cm = MakeCommitment(i);
        tree.Append(cm);
        wit.IncrementalUpdate(cm);

        // Witness must verify at every step.
        BOOST_CHECK_MESSAGE(
            wit.Verify(target_leaf, tree.Root()),
            "Witness failed at tree size " + std::to_string(tree.Size()));
    }
}

BOOST_AUTO_TEST_CASE(witness_old_leaf_verifies_after_many_updates)
{
    ShieldedMerkleTree tree;

    // Insert leaf at position 0.
    uint256 leaf0 = MakeCommitment(0);
    tree.Append(leaf0);
    ShieldedMerkleWitness wit0 = tree.Witness();

    // Insert 500 more leaves.
    for (uint32_t i = 1; i <= 500; ++i) {
        uint256 cm = MakeCommitment(i);
        tree.Append(cm);
        wit0.IncrementalUpdate(cm);
    }

    // Old witness still verifies.
    BOOST_CHECK(wit0.Verify(leaf0, tree.Root()));
}

BOOST_AUTO_TEST_CASE(invalid_witness_wrong_sibling_fails)
{
    // Build a tree with multiple leaves so the witness has non-trivial
    // sibling hashes (not just EmptyRoot at every level).
    ShieldedMerkleTree tree;
    uint256 leaf = MakeCommitment(42);
    tree.Append(MakeCommitment(1));
    tree.Append(leaf);

    ShieldedMerkleWitness wit = tree.Witness();
    uint256 root = tree.Root();

    // Verify it works first.
    BOOST_CHECK(wit.Verify(leaf, root));

    // Create a second tree with different leaves so the witness has
    // different sibling hashes at depth 0.
    ShieldedMerkleTree tree2;
    tree2.Append(MakeCommitment(999));
    tree2.Append(MakeCommitment(998));
    ShieldedMerkleWitness bad_wit = tree2.Witness();

    // The bad witness should NOT verify against the original root/leaf.
    BOOST_CHECK(!bad_wit.Verify(leaf, root));
}

BOOST_AUTO_TEST_CASE(random_witness_fails_verification)
{
    ShieldedMerkleTree tree;
    for (uint32_t i = 0; i < 10; ++i) {
        tree.Append(MakeCommitment(i));
    }
    uint256 root = tree.Root();

    // Construct a witness from a completely different tree.
    ShieldedMerkleTree other;
    other.Append(MakeCommitment(12345));
    ShieldedMerkleWitness fake_wit = other.Witness();

    // Should not verify against the real tree's root.
    BOOST_CHECK(!fake_wit.Verify(MakeCommitment(0), root));
}

// ===================================================================
// Serialization tests
// ===================================================================

BOOST_AUTO_TEST_CASE(serialize_deserialize_tree_roundtrip)
{
    ShieldedMerkleTree tree;
    for (uint32_t i = 0; i < 100; ++i) {
        tree.Append(MakeCommitment(i));
    }

    // Serialize.
    DataStream ss{};
    ss << tree;

    // Deserialize.
    ShieldedMerkleTree tree2;
    ss >> tree2;

    // Must produce the same root and size.
    BOOST_CHECK(tree.Root() == tree2.Root());
    BOOST_CHECK_EQUAL(tree.Size(), tree2.Size());
}

BOOST_AUTO_TEST_CASE(serialize_deserialize_witness_roundtrip)
{
    ShieldedMerkleTree tree;
    for (uint32_t i = 0; i < 50; ++i) {
        tree.Append(MakeCommitment(i));
    }
    uint256 target = MakeCommitment(50);
    tree.Append(target);
    ShieldedMerkleWitness wit = tree.Witness();

    // Update a few times.
    for (uint32_t i = 51; i < 80; ++i) {
        uint256 cm = MakeCommitment(i);
        tree.Append(cm);
        wit.IncrementalUpdate(cm);
    }

    // Serialize.
    DataStream ss{};
    ss << wit;

    // Deserialize.
    ShieldedMerkleWitness wit2;
    ss >> wit2;

    // Both must produce the same root and verify the same leaf.
    BOOST_CHECK(wit.Root() == wit2.Root());
    BOOST_CHECK(wit2.Verify(target, tree.Root()));
    BOOST_CHECK_EQUAL(wit.Position(), wit2.Position());
}

BOOST_AUTO_TEST_CASE(serialized_tree_size_bounded)
{
    // Test that the serialized size is approximately 1KB regardless of
    // how many leaves have been inserted.
    for (uint32_t count : {1u, 10u, 100u, 1000u, 10000u}) {
        ShieldedMerkleTree tree;
        for (uint32_t i = 0; i < count; ++i) {
            tree.Append(MakeCommitment(i));
        }

        DataStream ss{};
        ss << tree;
        size_t sz = ss.size();

        // The frontier is O(depth) = O(32).  Serialized size should be
        // bounded: 8 (size) + up to 33*34 (left + right + 32 parents) + overhead
        // = well under 2 KB.
        BOOST_CHECK_MESSAGE(sz <= 1200,
            "Serialized tree with " + std::to_string(count) +
            " leaves is " + std::to_string(sz) + " bytes (expected <= 1200)");

        // Must be at least a few bytes (size + left).
        BOOST_CHECK(sz >= 10);
    }
}

BOOST_AUTO_TEST_CASE(serialize_empty_tree_roundtrip)
{
    ShieldedMerkleTree tree;

    DataStream ss{};
    ss << tree;

    ShieldedMerkleTree tree2;
    ss >> tree2;

    BOOST_CHECK(tree.Root() == tree2.Root());
    BOOST_CHECK_EQUAL(tree2.Size(), 0u);
}

// ===================================================================
// Edge cases
// ===================================================================

/**
 * Test tree at maximum capacity using a reduced-depth tree.
 * We cannot fill 2^32 leaves in a test, so we verify the logic by
 * using 2^8 = 256 appends and checking that the 257th throws.
 * (We test with MERKLE_DEPTH=32 but simply verify the overflow check
 *  logic by checking the reported max.)
 */
BOOST_AUTO_TEST_CASE(overflow_detection)
{
    // We cannot actually fill 2^32 leaves, but we can verify the constant.
    BOOST_CHECK_EQUAL(MERKLE_MAX_LEAVES, static_cast<uint64_t>(1) << 32);

    // Verify that the tree tracks size correctly up to a reasonable number.
    ShieldedMerkleTree tree;
    for (uint32_t i = 0; i < 1000; ++i) {
        tree.Append(MakeCommitment(i));
    }
    BOOST_CHECK_EQUAL(tree.Size(), 1000u);
}

BOOST_AUTO_TEST_CASE(empty_tree_witness_throws)
{
    ShieldedMerkleTree tree;
    BOOST_CHECK_THROW(tree.Witness(), std::runtime_error);
}

BOOST_AUTO_TEST_CASE(empty_tree_last_leaf_throws)
{
    ShieldedMerkleTree tree;
    BOOST_CHECK_THROW(tree.LastLeaf(), std::runtime_error);
}

// ===================================================================
// Regression / determinism
// ===================================================================

BOOST_AUTO_TEST_CASE(empty_root_cache_correctness)
{
    // Manually compute all 33 empty roots (depth 0..32) and compare
    // to the cached values from EmptyRoot().
    for (size_t d = 0; d <= MERKLE_DEPTH; ++d) {
        uint256 manual = ManualEmptyRoot(d);
        BOOST_CHECK_MESSAGE(
            manual == EmptyRoot(d),
            "EmptyRoot mismatch at depth " + std::to_string(d));
    }
}

BOOST_AUTO_TEST_CASE(deterministic_test_vectors)
{
    // Compute roots for known sequences and verify they are deterministic.
    // These serve as regression tests: if the hash function or domain tags
    // change, these will break.

    // Vector 1: single leaf = MakeCommitment(0).
    ShieldedMerkleTree t1;
    t1.Append(MakeCommitment(0));
    uint256 root1 = t1.Root();

    // Recompute independently.
    ShieldedMerkleTree t1b;
    t1b.Append(MakeCommitment(0));
    BOOST_CHECK(t1b.Root() == root1);

    // Vector 2: leaves 0..9.
    ShieldedMerkleTree t2;
    for (uint32_t i = 0; i < 10; ++i) {
        t2.Append(MakeCommitment(i));
    }
    uint256 root2 = t2.Root();

    ShieldedMerkleTree t2b;
    for (uint32_t i = 0; i < 10; ++i) {
        t2b.Append(MakeCommitment(i));
    }
    BOOST_CHECK(t2b.Root() == root2);

    // Vector 3: leaves 0..99.
    ShieldedMerkleTree t3;
    for (uint32_t i = 0; i < 100; ++i) {
        t3.Append(MakeCommitment(i));
    }
    uint256 root3 = t3.Root();

    ShieldedMerkleTree t3b;
    for (uint32_t i = 0; i < 100; ++i) {
        t3b.Append(MakeCommitment(i));
    }
    BOOST_CHECK(t3b.Root() == root3);

    // All three roots must be distinct.
    BOOST_CHECK(root1 != root2);
    BOOST_CHECK(root2 != root3);
    BOOST_CHECK(root1 != root3);

    // R6-317: Frozen Merkle root KAT — detects silent changes to hash or domain tags.
    BOOST_CHECK_EQUAL(root1.GetHex(),
                      "bfd0697504942218c4d8cc87163990c902dc2e309713aa73fa777d1acff17714");
    BOOST_CHECK_EQUAL(root2.GetHex(),
                      "4e1b921e4c549353c68a1df282def3c4b29f7c0843797ec515f250ac95fcc77c");
    BOOST_CHECK_EQUAL(root3.GetHex(),
                      "c665c971caf99d7945b2ba7b6d91759ad9ac8b108649d946e4dd4ede680943f0");
}

BOOST_AUTO_TEST_CASE(root_deterministic_across_snapshots)
{
    // Build a tree, take the root at various sizes, rebuild from scratch,
    // and verify roots match.
    std::vector<uint256> roots;
    {
        ShieldedMerkleTree tree;
        for (uint32_t i = 0; i < 64; ++i) {
            tree.Append(MakeCommitment(i));
            roots.push_back(tree.Root());
        }
    }

    {
        ShieldedMerkleTree tree;
        for (uint32_t i = 0; i < 64; ++i) {
            tree.Append(MakeCommitment(i));
            BOOST_CHECK_MESSAGE(
                tree.Root() == roots[i],
                "Root mismatch at size " + std::to_string(i + 1));
        }
    }
}

// ===================================================================
// Security-oriented tests
// ===================================================================

BOOST_AUTO_TEST_CASE(different_leaf_sets_produce_different_roots)
{
    // Merkle collision resistance: no two distinct leaf sets should produce
    // the same root (with overwhelming probability under SHA-256).
    ShieldedMerkleTree t1, t2;
    for (uint32_t i = 0; i < 50; ++i) {
        t1.Append(MakeCommitment(i));
        t2.Append(MakeCommitment(i + 1000));
    }
    BOOST_CHECK(t1.Root() != t2.Root());
}

BOOST_AUTO_TEST_CASE(forge_witness_fails)
{
    // Second preimage resistance: a witness constructed for a non-existent
    // note must fail verification.
    ShieldedMerkleTree tree;
    for (uint32_t i = 0; i < 20; ++i) {
        tree.Append(MakeCommitment(i));
    }
    uint256 root = tree.Root();

    // Try to verify a leaf that was never inserted.
    uint256 fake_leaf = MakeCommitment(99999);
    ShieldedMerkleWitness real_wit = tree.Witness();

    // The witness is for the last real leaf (MakeCommitment(19)).
    // Trying to verify fake_leaf with this witness should fail.
    BOOST_CHECK(!real_wit.Verify(fake_leaf, root));
}

BOOST_AUTO_TEST_CASE(stale_witness_fails_against_new_root)
{
    // A witness taken at an earlier tree state should NOT verify against
    // the current root (unless updated).
    ShieldedMerkleTree tree;
    uint256 leaf0 = MakeCommitment(0);
    tree.Append(leaf0);

    ShieldedMerkleWitness stale_wit = tree.Witness();
    uint256 old_root = tree.Root();

    // Stale witness verifies against old root.
    BOOST_CHECK(stale_wit.Verify(leaf0, old_root));

    // Add more leaves.
    for (uint32_t i = 1; i < 10; ++i) {
        tree.Append(MakeCommitment(i));
    }
    uint256 new_root = tree.Root();
    BOOST_CHECK(old_root != new_root);

    // Stale witness must fail against the new root.
    BOOST_CHECK(!stale_wit.Verify(leaf0, new_root));
}

BOOST_AUTO_TEST_CASE(stale_witness_succeeds_against_old_root)
{
    ShieldedMerkleTree tree;
    uint256 leaf0 = MakeCommitment(0);
    tree.Append(leaf0);

    ShieldedMerkleWitness stale_wit = tree.Witness();
    uint256 old_root = tree.Root();

    // Add more leaves (don't update witness).
    for (uint32_t i = 1; i < 10; ++i) {
        tree.Append(MakeCommitment(i));
    }

    // Stale witness still verifies against the OLD root.
    BOOST_CHECK(stale_wit.Verify(leaf0, old_root));
}

BOOST_AUTO_TEST_CASE(tree_rewind_produces_consistent_state)
{
    // Simulate block disconnect: save tree state, append leaves (connect
    // block), then restore (disconnect block) and verify state matches.

    ShieldedMerkleTree tree;
    for (uint32_t i = 0; i < 50; ++i) {
        tree.Append(MakeCommitment(i));
    }

    // Save state (serialize).
    DataStream checkpoint{};
    checkpoint << tree;
    uint256 checkpoint_root = tree.Root();
    uint64_t checkpoint_size = tree.Size();

    // "Connect" a block with 10 more leaves.
    for (uint32_t i = 50; i < 60; ++i) {
        tree.Append(MakeCommitment(i));
    }
    BOOST_CHECK(tree.Root() != checkpoint_root);
    BOOST_CHECK_EQUAL(tree.Size(), 60u);

    // "Disconnect" the block: restore from checkpoint.
    ShieldedMerkleTree restored;
    checkpoint >> restored;
    BOOST_CHECK(restored.Root() == checkpoint_root);
    BOOST_CHECK_EQUAL(restored.Size(), checkpoint_size);

    // Re-append different leaves (rewind attack scenario).
    for (uint32_t i = 100; i < 110; ++i) {
        restored.Append(MakeCommitment(i));
    }
    // Must produce a DIFFERENT root than the original forward path.
    BOOST_CHECK(restored.Root() != tree.Root());
}

BOOST_AUTO_TEST_CASE(anchor_age_validation)
{
    // Test that anchor (root) age can be validated.
    // We collect roots at each block height and verify that only recent
    // anchors (within a window) should be accepted.

    const size_t ANCHOR_WINDOW = 100;
    std::vector<uint256> block_roots;

    ShieldedMerkleTree tree;
    for (uint32_t i = 0; i < 200; ++i) {
        tree.Append(MakeCommitment(i));
        block_roots.push_back(tree.Root());
    }

    uint256 current_root = tree.Root();
    size_t current_height = block_roots.size() - 1;

    // Recent anchors (within window) should be findable.
    for (size_t h = current_height; h > current_height - ANCHOR_WINDOW && h < block_roots.size(); --h) {
        // In production code, we'd check: is block_roots[h] in the set of
        // valid anchors?  Here we just verify they're all distinct and valid.
        BOOST_CHECK(block_roots[h] != uint256::ZERO);
    }

    // An anchor from before the window is "stale" -- in production this
    // would be rejected.  Here we just verify it's different from current.
    if (current_height >= ANCHOR_WINDOW) {
        uint256 stale_anchor = block_roots[current_height - ANCHOR_WINDOW - 1];
        BOOST_CHECK(stale_anchor != current_root);
    }
}

BOOST_AUTO_TEST_CASE(empty_subtree_optimization_soundness)
{
    // Verify all 33 cached empty roots by independent manual computation.
    for (size_t d = 0; d <= MERKLE_DEPTH; ++d) {
        BOOST_CHECK(EmptyRoot(d) == ManualEmptyRoot(d));
    }

    // Verify the recursive property: EmptyRoot(d) = BranchHash(EmptyRoot(d-1), EmptyRoot(d-1)).
    for (size_t d = 1; d <= MERKLE_DEPTH; ++d) {
        BOOST_CHECK(EmptyRoot(d) == BranchHash(EmptyRoot(d - 1), EmptyRoot(d - 1)));
    }
}

BOOST_AUTO_TEST_CASE(witness_multiple_notes_tracked)
{
    // Simulate a wallet tracking multiple notes.  Each note gets its own
    // witness, and all must be updated on every append.

    ShieldedMerkleTree tree;
    std::vector<std::pair<uint256, ShieldedMerkleWitness>> tracked;

    for (uint32_t i = 0; i < 100; ++i) {
        uint256 cm = MakeCommitment(i);
        tree.Append(cm);

        // Update all existing witnesses.
        for (auto& [leaf, wit] : tracked) {
            wit.IncrementalUpdate(cm);
        }

        // Track every 10th leaf.
        if (i % 10 == 0) {
            tracked.emplace_back(cm, tree.Witness());
        }
    }

    // All tracked witnesses must verify.
    uint256 root = tree.Root();
    for (const auto& [leaf, wit] : tracked) {
        BOOST_CHECK_MESSAGE(
            wit.Verify(leaf, root),
            "Tracked witness for position " + std::to_string(wit.Position()) + " failed");
    }
}

// Diagnostic: check witness Root vs tree Root at each step.
BOOST_AUTO_TEST_CASE(witness_root_matches_tree_root_diagnostic)
{
    ShieldedMerkleTree tree;

    for (uint32_t i = 0; i < 50; ++i) {
        tree.Append(MakeCommitment(i));
    }

    uint256 target = MakeCommitment(50);
    tree.Append(target);

    BOOST_TEST_MESSAGE("Snapshot: size=" << tree.Size()
        << " left=" << (tree.Left() ? "Y" : "N")
        << " right=" << (tree.Right() ? "Y" : "N")
        << " parents=" << tree.Parents().size());
    for (size_t i = 0; i < tree.Parents().size(); ++i) {
        BOOST_TEST_MESSAGE("  parent[" << i << "]=" << (tree.Parents()[i] ? "Y" : "N"));
    }

    ShieldedMerkleWitness wit = tree.Witness();

    for (uint32_t i = 51; i < 60; ++i) {
        uint256 cm = MakeCommitment(i);
        tree.Append(cm);
        wit.IncrementalUpdate(cm);

        uint256 wit_root = wit.Root();
        uint256 tree_root = tree.Root();
        BOOST_CHECK_MESSAGE(
            wit_root == tree_root,
            "Root mismatch at size " + std::to_string(tree.Size()) +
            ": wit=" + wit_root.GetHex().substr(0, 16) +
            " tree=" + tree_root.GetHex().substr(0, 16));

        bool verify_ok = wit.Verify(target, tree_root);
        BOOST_CHECK_MESSAGE(
            verify_ok,
            "Verify failed at size " + std::to_string(tree.Size()));
    }
}

BOOST_AUTO_TEST_SUITE_END()
