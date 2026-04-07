// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <random.h>
#include <shielded/nullifier.h>
#include <test/util/shielded_account_registry_test_util.h>
#include <test/util/setup_common.h>
#include <test/util/shielded_smile_test_util.h>

#include <boost/test/unit_test.hpp>

#include <algorithm>
#include <atomic>
#include <filesystem>
#include <optional>
#include <thread>
#include <vector>

namespace {
struct LegacyShieldedStateDisk
{
    shielded::ShieldedMerkleTree tree;
    std::vector<uint256> anchor_roots;
    uint256 tip_hash;
    int32_t tip_height{-1};
    CAmount pool_balance{0};

    SERIALIZE_METHODS(LegacyShieldedStateDisk, obj)
    {
        READWRITE(obj.tree, obj.anchor_roots, obj.tip_hash, obj.tip_height, obj.pool_balance);
    }
};

struct PositionalShieldedStateDisk
{
    shielded::ShieldedMerkleTree tree;
    std::vector<uint256> anchor_roots;
    uint256 tip_hash;
    int32_t tip_height{-1};
    CAmount pool_balance{0};
    std::optional<uint256> commitment_index_digest;
    std::optional<shielded::registry::ShieldedAccountRegistrySnapshot> account_registry_snapshot;

    template <typename Stream>
    void Serialize(Stream& s) const
    {
        ::Serialize(s, tree);
        ::Serialize(s, anchor_roots);
        ::Serialize(s, tip_hash);
        ::Serialize(s, tip_height);
        ::Serialize(s, pool_balance);
        if (commitment_index_digest.has_value()) {
            ::Serialize(s, *commitment_index_digest);
        }
        const bool has_account_registry_snapshot = account_registry_snapshot.has_value();
        ::Serialize(s, has_account_registry_snapshot);
        if (has_account_registry_snapshot) {
            ::Serialize(s, *account_registry_snapshot);
        }
    }
};

struct RegistryPayloadStoreGuard
{
    explicit RegistryPayloadStoreGuard(const fs::path& db_path)
    {
        shielded::registry::ShieldedAccountRegistryState::ResetPayloadStore();
        BOOST_REQUIRE(shielded::registry::ShieldedAccountRegistryState::ConfigurePayloadStore(
            db_path,
            1 << 20,
            /*memory_only=*/false,
            /*wipe_data=*/true));
    }

    ~RegistryPayloadStoreGuard()
    {
        shielded::registry::ShieldedAccountRegistryState::ResetPayloadStore();
    }
};
} // namespace

BOOST_FIXTURE_TEST_SUITE(nullifier_set_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(insert_and_contains)
{
    NullifierSet ns(m_args.GetDataDirNet() / "test_nf", 1 << 20, /*memory_only=*/false, /*wipe_data=*/true);
    const Nullifier nf = GetRandHash();

    BOOST_CHECK(!ns.Contains(nf));
    BOOST_CHECK(ns.Insert({nf}));
    BOOST_CHECK(ns.Contains(nf));
}

BOOST_AUTO_TEST_CASE(batch_insert_and_any_exist)
{
    NullifierSet ns(m_args.GetDataDirNet() / "test_nf2", 1 << 20, /*memory_only=*/false, /*wipe_data=*/true);
    std::vector<Nullifier> batch;
    batch.reserve(100);
    for (int i = 0; i < 100; ++i) {
        batch.push_back(GetRandHash());
    }

    BOOST_CHECK(!ns.AnyExist(batch));
    BOOST_CHECK(ns.Insert(batch));
    BOOST_CHECK(ns.AnyExist(batch));
    BOOST_CHECK(ns.AnyExist({batch[50]}));
}

BOOST_AUTO_TEST_CASE(remove_and_verify)
{
    NullifierSet ns(m_args.GetDataDirNet() / "test_nf3", 1 << 20, /*memory_only=*/false, /*wipe_data=*/true);
    const Nullifier nf = GetRandHash();

    BOOST_CHECK(ns.Insert({nf}));
    BOOST_CHECK(ns.Contains(nf));
    BOOST_CHECK(ns.Remove({nf}));
    BOOST_CHECK(!ns.Contains(nf));
}

BOOST_AUTO_TEST_CASE(settlement_anchor_insert_remove_and_iterate)
{
    NullifierSet ns(m_args.GetDataDirNet() / "test_nf_settlement_anchors", 1 << 20, /*memory_only=*/false, /*wipe_data=*/true);
    const uint256 anchor_a = GetRandHash();
    const uint256 anchor_b = GetRandHash();
    const ConfirmedSettlementAnchorState state_a{anchor_a, /*created_height=*/101};
    const ConfirmedSettlementAnchorState state_b{anchor_b, /*created_height=*/102};

    BOOST_CHECK(!ns.ContainsSettlementAnchor(anchor_a));
    BOOST_CHECK(ns.InsertSettlementAnchors({state_a, state_b}));
    BOOST_CHECK(ns.ContainsSettlementAnchor(anchor_a));
    BOOST_CHECK(ns.ContainsSettlementAnchor(anchor_b));
    BOOST_REQUIRE(ns.GetSettlementAnchorState(anchor_a).has_value());
    BOOST_CHECK_EQUAL(ns.GetSettlementAnchorState(anchor_a)->created_height, state_a.created_height);
    BOOST_REQUIRE(ns.GetSettlementAnchorState(anchor_b).has_value());
    BOOST_CHECK_EQUAL(ns.GetSettlementAnchorState(anchor_b)->created_height, state_b.created_height);

    std::vector<uint256> persisted;
    BOOST_CHECK(ns.ForEachPersistedSettlementAnchor([&](const uint256& anchor) {
        persisted.push_back(anchor);
        return true;
    }));
    BOOST_CHECK_EQUAL(persisted.size(), 2U);
    BOOST_CHECK(std::find(persisted.begin(), persisted.end(), anchor_a) != persisted.end());
    BOOST_CHECK(std::find(persisted.begin(), persisted.end(), anchor_b) != persisted.end());

    std::vector<ConfirmedSettlementAnchorState> persisted_states;
    BOOST_CHECK(ns.ForEachPersistedSettlementAnchorState([&](const ConfirmedSettlementAnchorState& anchor_state) {
        persisted_states.push_back(anchor_state);
        return true;
    }));
    BOOST_CHECK_EQUAL(persisted_states.size(), 2U);
    BOOST_CHECK(std::find(persisted_states.begin(), persisted_states.end(), state_a) != persisted_states.end());
    BOOST_CHECK(std::find(persisted_states.begin(), persisted_states.end(), state_b) != persisted_states.end());

    BOOST_CHECK(ns.RemoveSettlementAnchors({anchor_a}));
    BOOST_CHECK(!ns.ContainsSettlementAnchor(anchor_a));
    BOOST_CHECK(!ns.GetSettlementAnchorState(anchor_a).has_value());
    BOOST_CHECK(ns.ContainsSettlementAnchor(anchor_b));
}

BOOST_AUTO_TEST_CASE(netting_manifest_insert_remove_and_iterate)
{
    NullifierSet ns(m_args.GetDataDirNet() / "test_nf_netting_manifests", 1 << 20, /*memory_only=*/false, /*wipe_data=*/true);
    const uint256 manifest_a = GetRandHash();
    const uint256 manifest_b = GetRandHash();
    const ConfirmedNettingManifestState state_a{manifest_a, /*created_height=*/101, /*settlement_window=*/144};
    const ConfirmedNettingManifestState state_b{manifest_b, /*created_height=*/102, /*settlement_window=*/288};

    BOOST_CHECK(!ns.ContainsNettingManifest(manifest_a));
    BOOST_CHECK(ns.InsertNettingManifests({state_a, state_b}));
    BOOST_CHECK(ns.ContainsNettingManifest(manifest_a));
    BOOST_CHECK(ns.ContainsNettingManifest(manifest_b));
    BOOST_REQUIRE(ns.GetNettingManifestState(manifest_a).has_value());
    BOOST_CHECK_EQUAL(ns.GetNettingManifestState(manifest_a)->created_height, state_a.created_height);
    BOOST_CHECK_EQUAL(ns.GetNettingManifestState(manifest_b)->settlement_window, state_b.settlement_window);

    std::vector<uint256> persisted;
    BOOST_CHECK(ns.ForEachPersistedNettingManifest([&](const uint256& manifest_id) {
        persisted.push_back(manifest_id);
        return true;
    }));
    BOOST_CHECK_EQUAL(persisted.size(), 2U);
    BOOST_CHECK(std::find(persisted.begin(), persisted.end(), manifest_a) != persisted.end());
    BOOST_CHECK(std::find(persisted.begin(), persisted.end(), manifest_b) != persisted.end());

    std::vector<ConfirmedNettingManifestState> persisted_states;
    BOOST_CHECK(ns.ForEachPersistedNettingManifestState([&](const ConfirmedNettingManifestState& manifest_state) {
        persisted_states.push_back(manifest_state);
        return true;
    }));
    BOOST_CHECK_EQUAL(persisted_states.size(), 2U);
    BOOST_CHECK(std::find(persisted_states.begin(), persisted_states.end(), state_a) != persisted_states.end());
    BOOST_CHECK(std::find(persisted_states.begin(), persisted_states.end(), state_b) != persisted_states.end());

    BOOST_CHECK(ns.RemoveNettingManifests({manifest_a}));
    BOOST_CHECK(!ns.ContainsNettingManifest(manifest_a));
    BOOST_CHECK(!ns.GetNettingManifestState(manifest_a).has_value());
    BOOST_CHECK(ns.ContainsNettingManifest(manifest_b));
}

BOOST_AUTO_TEST_CASE(count_nullifiers_tracks_exact_entries)
{
    NullifierSet ns(m_args.GetDataDirNet() / "test_nf3_count", 1 << 20, /*memory_only=*/false, /*wipe_data=*/true);
    const Nullifier a = GetRandHash();
    const Nullifier b = GetRandHash();

    BOOST_CHECK_EQUAL(ns.CountNullifiers(), 0U);
    BOOST_CHECK(ns.Insert({a, b}));
    BOOST_CHECK_EQUAL(ns.CountNullifiers(), 2U);

    // Duplicate inserts are idempotent in the DB keyspace.
    BOOST_CHECK(ns.Insert({a}));
    BOOST_CHECK_EQUAL(ns.CountNullifiers(), 2U);

    BOOST_CHECK(ns.Remove({a}));
    BOOST_CHECK_EQUAL(ns.CountNullifiers(), 1U);
    BOOST_CHECK(ns.Remove({b}));
    BOOST_CHECK_EQUAL(ns.CountNullifiers(), 0U);
}

BOOST_AUTO_TEST_CASE(count_nullifiers_remove_ignores_missing_and_duplicate_entries)
{
    NullifierSet ns(m_args.GetDataDirNet() / "test_nf3_count_remove_missing", 1 << 20, /*memory_only=*/false, /*wipe_data=*/true);
    const Nullifier a = GetRandHash();
    const Nullifier b = GetRandHash();
    const Nullifier missing = GetRandHash();

    BOOST_CHECK(ns.Insert({a, b}));
    BOOST_CHECK_EQUAL(ns.CountNullifiers(), 2U);

    BOOST_CHECK(ns.Remove({a, a, missing}));
    BOOST_CHECK_EQUAL(ns.CountNullifiers(), 1U);
    BOOST_CHECK(!ns.Contains(a));
    BOOST_CHECK(ns.Contains(b));

    BOOST_CHECK(ns.Remove({missing}));
    BOOST_CHECK_EQUAL(ns.CountNullifiers(), 1U);

    BOOST_CHECK(ns.Remove({b}));
    BOOST_CHECK_EQUAL(ns.CountNullifiers(), 0U);
}

BOOST_AUTO_TEST_CASE(count_nullifiers_reloads_persisted_counter_on_restart)
{
    const std::filesystem::path db_path = m_args.GetDataDirNet() / "test_nf_count_restart";
    const Nullifier a = GetRandHash();
    const Nullifier b = GetRandHash();

    {
        NullifierSet ns(db_path, 1 << 20, /*memory_only=*/false, /*wipe_data=*/true);
        BOOST_CHECK(ns.Insert({a, b}));
        BOOST_CHECK_EQUAL(ns.CountNullifiers(), 2U);
    }

    {
        NullifierSet restarted(db_path, 1 << 20, /*memory_only=*/false, /*wipe_data=*/false);
        BOOST_CHECK(restarted.Contains(a));
        BOOST_CHECK(restarted.Contains(b));
        BOOST_CHECK_EQUAL(restarted.CountNullifiers(), 2U);
        BOOST_CHECK_EQUAL(restarted.CountNullifiersSlow(), 2U);
    }
}

BOOST_AUTO_TEST_CASE(count_nullifiers_backfills_missing_counter_key)
{
    const std::filesystem::path db_path = m_args.GetDataDirNet() / "test_nf_count_backfill";
    const Nullifier a = GetRandHash();
    const Nullifier b = GetRandHash();

    {
        NullifierSet ns(db_path, 1 << 20, /*memory_only=*/false, /*wipe_data=*/true);
        BOOST_CHECK(ns.Insert({a, b}));
        BOOST_CHECK_EQUAL(ns.CountNullifiers(), 2U);
    }

    {
        CDBWrapper db({.path = db_path, .cache_bytes = 1 << 20, .memory_only = false, .wipe_data = false, .obfuscate = true});
        BOOST_REQUIRE(db.Erase(std::make_pair(uint8_t{'C'}, uint8_t{0})));
    }

    {
        NullifierSet restarted(db_path, 1 << 20, /*memory_only=*/false, /*wipe_data=*/false);
        BOOST_CHECK_EQUAL(restarted.CountNullifiers(), 2U);
        BOOST_CHECK_EQUAL(restarted.CountNullifiersSlow(), 2U);
    }

    {
        CDBWrapper db({.path = db_path, .cache_bytes = 1 << 20, .memory_only = false, .wipe_data = false, .obfuscate = true});
        uint64_t persisted_count{0};
        BOOST_REQUIRE(db.Read(std::make_pair(uint8_t{'C'}, uint8_t{0}), persisted_count));
        BOOST_CHECK_EQUAL(persisted_count, 2U);
    }
}

BOOST_AUTO_TEST_CASE(concurrent_reads)
{
    NullifierSet ns(m_args.GetDataDirNet() / "test_nf4", 1 << 20, /*memory_only=*/false, /*wipe_data=*/true);
    std::vector<Nullifier> existing;
    existing.reserve(1000);
    for (int i = 0; i < 1000; ++i) {
        existing.push_back(GetRandHash());
    }
    BOOST_CHECK(ns.Insert(existing));

    std::vector<std::thread> readers;
    std::atomic<int> hits{0};
    for (int t = 0; t < 8; ++t) {
        readers.emplace_back([&, t] {
            for (int i = t * 125; i < (t + 1) * 125 && i < 1000; ++i) {
                if (ns.Contains(existing[i])) {
                    ++hits;
                }
            }
        });
    }
    for (auto& reader : readers) {
        reader.join();
    }
    BOOST_CHECK_EQUAL(hits.load(), 1000);
}

BOOST_AUTO_TEST_CASE(duplicate_insert_idempotent)
{
    NullifierSet ns(m_args.GetDataDirNet() / "test_nf5", 1 << 20, /*memory_only=*/false, /*wipe_data=*/true);
    const Nullifier nf = GetRandHash();

    BOOST_CHECK(ns.Insert({nf}));
    BOOST_CHECK(ns.Insert({nf}));
    BOOST_CHECK(ns.Contains(nf));
    BOOST_CHECK(ns.Remove({nf}));
    BOOST_CHECK(!ns.Contains(nf));
}

BOOST_AUTO_TEST_CASE(nonexistent_nullifier_returns_false)
{
    NullifierSet ns(m_args.GetDataDirNet() / "test_nf6", 1 << 20, /*memory_only=*/false, /*wipe_data=*/true);
    BOOST_CHECK(!ns.Contains(GetRandHash()));
    BOOST_CHECK(!ns.AnyExist({GetRandHash(), GetRandHash()}));
}

BOOST_AUTO_TEST_CASE(null_nullifier_rejected)
{
    NullifierSet ns(m_args.GetDataDirNet() / "test_nf7", 1 << 20, /*memory_only=*/false, /*wipe_data=*/true);
    BOOST_CHECK(!ns.Contains(Nullifier::ZERO));
    BOOST_CHECK(!ns.Insert({Nullifier::ZERO}));
    BOOST_CHECK(!ns.Remove({Nullifier::ZERO}));
}

// R5-306: Consensus-level double-spend rejection test.
// Verifies that AnyExist() correctly detects already-spent nullifiers,
// which is the mechanism ConnectBlock uses to reject double-spends.
BOOST_AUTO_TEST_CASE(double_spend_rejection_via_any_exist)
{
    NullifierSet ns(m_args.GetDataDirNet() / "test_nf_dbl", 1 << 20, /*memory_only=*/false, /*wipe_data=*/true);

    // Simulate block 1: insert nullifier from first spend
    const Nullifier nf_spend1 = GetRandHash();
    const Nullifier nf_spend2 = GetRandHash();
    BOOST_CHECK(ns.Insert({nf_spend1}));

    // Simulate block 2: a transaction tries to re-spend the same nullifier
    // ConnectBlock calls AnyExist() on the block's nullifiers before insertion
    BOOST_CHECK(ns.AnyExist({nf_spend1})); // MUST detect the double-spend

    // A transaction with a mix of new and duplicate nullifiers must also be detected
    BOOST_CHECK(ns.AnyExist({nf_spend2, nf_spend1})); // nf_spend1 is the duplicate

    // A block with only new nullifiers must pass
    BOOST_CHECK(!ns.AnyExist({nf_spend2}));

    // After inserting the new nullifier, it too must be detected
    BOOST_CHECK(ns.Insert({nf_spend2}));
    BOOST_CHECK(ns.AnyExist({nf_spend2}));
}

// R5-307: DisconnectBlock nullifier rollback test.
// Verifies that Remove() correctly makes nullifiers spendable again after reorg.
BOOST_AUTO_TEST_CASE(disconnect_rollback_enables_respend)
{
    NullifierSet ns(m_args.GetDataDirNet() / "test_nf_rollback", 1 << 20, /*memory_only=*/false, /*wipe_data=*/true);

    // Simulate ConnectBlock: insert nullifiers from block N
    const Nullifier nf_a = GetRandHash();
    const Nullifier nf_b = GetRandHash();
    const Nullifier nf_c = GetRandHash();
    BOOST_CHECK(ns.Insert({nf_a, nf_b, nf_c}));
    BOOST_CHECK(ns.Contains(nf_a));
    BOOST_CHECK(ns.Contains(nf_b));
    BOOST_CHECK(ns.Contains(nf_c));

    // Simulate DisconnectBlock: remove nullifiers from block N
    BOOST_CHECK(ns.Remove({nf_a, nf_b, nf_c}));

    // After rollback, all nullifiers must be spendable again
    BOOST_CHECK(!ns.Contains(nf_a));
    BOOST_CHECK(!ns.Contains(nf_b));
    BOOST_CHECK(!ns.Contains(nf_c));
    BOOST_CHECK(!ns.AnyExist({nf_a, nf_b, nf_c}));

    // Re-inserting (as if a different block re-spends them) must succeed
    BOOST_CHECK(ns.Insert({nf_a}));
    BOOST_CHECK(ns.Contains(nf_a));

    // Verify the DB count is correct after the full cycle
    BOOST_CHECK_EQUAL(ns.CountNullifiers(), 1U);
}

// R5-306 extended: Pool balance tracking across connect/disconnect cycle.
BOOST_AUTO_TEST_CASE(pool_balance_connect_disconnect_cycle)
{
    NullifierSet ns(m_args.GetDataDirNet() / "test_nf_pool", 1 << 20, /*memory_only=*/false, /*wipe_data=*/true);

    // Initial pool balance: 0
    CAmount balance{0};
    BOOST_CHECK(ns.ReadPoolBalance(balance));
    BOOST_CHECK_EQUAL(balance, 0);

    // Simulate ConnectBlock: shielding 10000 satoshis
    BOOST_CHECK(ns.WritePoolBalance(10000));
    BOOST_CHECK(ns.ReadPoolBalance(balance));
    BOOST_CHECK_EQUAL(balance, 10000);

    // Simulate another ConnectBlock: shielding 5000 more
    BOOST_CHECK(ns.WritePoolBalance(15000));
    BOOST_CHECK(ns.ReadPoolBalance(balance));
    BOOST_CHECK_EQUAL(balance, 15000);

    // Simulate DisconnectBlock: rolling back the second block
    BOOST_CHECK(ns.WritePoolBalance(10000));
    BOOST_CHECK(ns.ReadPoolBalance(balance));
    BOOST_CHECK_EQUAL(balance, 10000);

    // Out-of-range balance must be rejected
    BOOST_CHECK(!ns.WritePoolBalance(-1));
}

BOOST_AUTO_TEST_CASE(persisted_shielded_state_roundtrip)
{
    RegistryPayloadStoreGuard payload_store_guard(
        m_args.GetDataDirNet() / "test_nf_persisted_state_registry_payloads");
    NullifierSet ns(m_args.GetDataDirNet() / "test_nf_persisted_state", 1 << 20, /*memory_only=*/false, /*wipe_data=*/true);
    shielded::ShieldedMerkleTree tree;
    tree.Append(GetRandHash());
    tree.Append(GetRandHash());

    const std::vector<uint256> anchor_roots{tree.Root(), GetRandHash()};
    const uint256 tip_hash = GetRandHash();
    constexpr int32_t tip_height{321};
    constexpr CAmount pool_balance{123456};
    auto account_registry =
        shielded::registry::ShieldedAccountRegistryState::WithConfiguredPayloadStore();
    const auto account_a = test::shielded::MakeDeterministicCompactPublicAccount(/*seed=*/0x91, /*value=*/4100);
    const auto account_b = test::shielded::MakeDeterministicCompactPublicAccount(/*seed=*/0x92, /*value=*/4200);
    const std::vector<shielded::registry::ShieldedAccountLeaf> leaf_payloads{
        *test::shielded::BuildDirectAccountLeaf(
            smile2::ComputeCompactPublicAccountHash(account_a),
            account_a),
        *test::shielded::BuildDirectAccountLeaf(
            smile2::ComputeCompactPublicAccountHash(account_b),
            account_b),
    };
    BOOST_REQUIRE(account_registry.Append(
        Span<const shielded::registry::ShieldedAccountLeaf>{leaf_payloads.data(), leaf_payloads.size()}));
    const auto account_registry_snapshot = account_registry.ExportPersistedSnapshot();
    BOOST_REQUIRE(account_registry_snapshot.IsValid());

    BOOST_CHECK(ns.WritePersistedState(tree,
                                      anchor_roots,
                                      tip_hash,
                                      tip_height,
                                      pool_balance,
                                      tree.CommitmentIndexDigest(),
                                      account_registry_snapshot));

    shielded::ShieldedMerkleTree restored_tree;
    std::vector<uint256> restored_anchor_roots;
    uint256 restored_tip_hash;
    int32_t restored_tip_height{-1};
    CAmount restored_pool_balance{0};
    std::optional<uint256> restored_commitment_index_digest;
    std::optional<shielded::registry::ShieldedAccountRegistryPersistedSnapshot>
        restored_account_registry_snapshot;
    BOOST_CHECK(ns.ReadPersistedState(
        restored_tree,
        restored_anchor_roots,
        restored_tip_hash,
        restored_tip_height,
        restored_pool_balance,
        restored_commitment_index_digest,
        restored_account_registry_snapshot));

    BOOST_CHECK_EQUAL(restored_tree.Size(), tree.Size());
    BOOST_CHECK_EQUAL(restored_tree.Root(), tree.Root());
    BOOST_REQUIRE(restored_commitment_index_digest.has_value());
    BOOST_CHECK_EQUAL(*restored_commitment_index_digest, *tree.CommitmentIndexDigest());
    BOOST_CHECK_EQUAL(restored_anchor_roots.size(), anchor_roots.size());
    for (size_t i = 0; i < anchor_roots.size(); ++i) {
        BOOST_CHECK_EQUAL(restored_anchor_roots[i], anchor_roots[i]);
    }
    BOOST_CHECK_EQUAL(restored_tip_hash, tip_hash);
    BOOST_CHECK_EQUAL(restored_tip_height, tip_height);
    BOOST_CHECK_EQUAL(restored_pool_balance, pool_balance);
    BOOST_REQUIRE(restored_account_registry_snapshot.has_value());
    const auto restored_account_registry =
        shielded::registry::ShieldedAccountRegistryState::RestorePersisted(
            *restored_account_registry_snapshot);
    BOOST_REQUIRE(restored_account_registry.has_value());
    BOOST_CHECK_EQUAL(restored_account_registry->Size(), account_registry.Size());
    BOOST_CHECK_EQUAL(restored_account_registry->Root(), account_registry.Root());
}

BOOST_AUTO_TEST_CASE(persisted_shielded_state_roundtrip_restores_commitment_index)
{
    struct CommitmentStoreResetGuard {
        ~CommitmentStoreResetGuard()
        {
            shielded::ShieldedMerkleTree::ResetCommitmentIndexStore();
        }
    } guard;

    shielded::ShieldedMerkleTree::ResetCommitmentIndexStore();
    const fs::path commitment_db_path = m_path_root / "test_nf_persisted_state_commitments";
    BOOST_REQUIRE(shielded::ShieldedMerkleTree::ConfigureCommitmentIndexStore(commitment_db_path,
                                                                              /*db_cache_bytes=*/1 << 20,
                                                                              /*lru_capacity=*/1024,
                                                                              /*memory_only=*/false,
                                                                              /*wipe_data=*/true));

    NullifierSet ns(m_args.GetDataDirNet() / "test_nf_persisted_state_with_index",
                    1 << 20,
                    /*memory_only=*/false,
                    /*wipe_data=*/true);
    shielded::ShieldedMerkleTree tree;
    std::vector<uint256> commitments;
    for (int i = 0; i < 8; ++i) {
        commitments.push_back(GetRandHash());
        tree.Append(commitments.back());
    }

    BOOST_CHECK(ns.WritePersistedState(tree,
                                      {tree.Root()},
                                      GetRandHash(),
                                      77,
                                      1234,
                                      tree.CommitmentIndexDigest(),
                                      std::nullopt));

    shielded::ShieldedMerkleTree restored_tree;
    std::vector<uint256> restored_anchor_roots;
    uint256 restored_tip_hash;
    int32_t restored_tip_height{-1};
    CAmount restored_pool_balance{0};
    std::optional<uint256> restored_commitment_index_digest;
    std::optional<shielded::registry::ShieldedAccountRegistryPersistedSnapshot>
        restored_account_registry_snapshot;
    BOOST_REQUIRE(ns.ReadPersistedState(restored_tree,
                                        restored_anchor_roots,
                                        restored_tip_hash,
                                        restored_tip_height,
                                        restored_pool_balance,
                                        restored_commitment_index_digest,
                                        restored_account_registry_snapshot));

    BOOST_REQUIRE(restored_commitment_index_digest.has_value());
    BOOST_CHECK_EQUAL(*restored_commitment_index_digest, *tree.CommitmentIndexDigest());
    BOOST_CHECK(!restored_account_registry_snapshot.has_value());
    BOOST_CHECK(restored_tree.HasCommitmentIndex());
    BOOST_CHECK_EQUAL(restored_tree.Size(), commitments.size());
    for (size_t i = 0; i < commitments.size(); ++i) {
        const auto restored = restored_tree.CommitmentAt(i);
        BOOST_REQUIRE(restored.has_value());
        BOOST_CHECK_EQUAL(*restored, commitments[i]);
    }
}

BOOST_AUTO_TEST_CASE(persisted_shielded_state_roundtrip_reads_legacy_state_without_digest)
{
    const std::filesystem::path db_path = m_args.GetDataDirNet() / "test_nf_persisted_state_legacy";
    {
        CDBWrapper db({.path = db_path, .cache_bytes = 1 << 20, .memory_only = false, .wipe_data = true, .obfuscate = true});

        shielded::ShieldedMerkleTree tree;
        tree.Append(GetRandHash());
        tree.Append(GetRandHash());

        LegacyShieldedStateDisk legacy_state;
        legacy_state.tree = tree;
        legacy_state.anchor_roots = {tree.Root(), GetRandHash()};
        legacy_state.tip_hash = GetRandHash();
        legacy_state.tip_height = 654;
        legacy_state.pool_balance = 98765;
        BOOST_REQUIRE(db.Write(std::make_pair(uint8_t{'S'}, uint8_t{0}), legacy_state, /*fSync=*/true));
    }

    NullifierSet ns(db_path, 1 << 20, /*memory_only=*/false, /*wipe_data=*/false);
    shielded::ShieldedMerkleTree restored_tree;
    std::vector<uint256> restored_anchor_roots;
    uint256 restored_tip_hash;
    int32_t restored_tip_height{-1};
    CAmount restored_pool_balance{0};
    std::optional<uint256> restored_commitment_index_digest;
    std::optional<shielded::registry::ShieldedAccountRegistryPersistedSnapshot>
        restored_account_registry_snapshot;
    BOOST_REQUIRE(ns.ReadPersistedState(restored_tree,
                                        restored_anchor_roots,
                                        restored_tip_hash,
                                        restored_tip_height,
                                        restored_pool_balance,
                                        restored_commitment_index_digest,
                                        restored_account_registry_snapshot));

    BOOST_CHECK_EQUAL(restored_tree.Size(), 2U);
    BOOST_CHECK_EQUAL(restored_anchor_roots.size(), 2U);
    BOOST_CHECK_EQUAL(restored_tip_height, 654);
    BOOST_CHECK_EQUAL(restored_pool_balance, 98765);
    BOOST_CHECK(!restored_commitment_index_digest.has_value());
    BOOST_CHECK(!restored_account_registry_snapshot.has_value());
}

BOOST_AUTO_TEST_CASE(persisted_shielded_state_roundtrip_reads_positional_state_without_digest)
{
    const std::filesystem::path db_path = m_args.GetDataDirNet() / "test_nf_persisted_state_positional_no_digest";
    {
        CDBWrapper db({.path = db_path, .cache_bytes = 1 << 20, .memory_only = false, .wipe_data = true, .obfuscate = true});

        shielded::ShieldedMerkleTree tree;
        tree.Append(GetRandHash());
        tree.Append(GetRandHash());

        PositionalShieldedStateDisk positional_state;
        positional_state.tree = tree;
        positional_state.anchor_roots = {tree.Root(), GetRandHash()};
        positional_state.tip_hash = GetRandHash();
        positional_state.tip_height = 211;
        positional_state.pool_balance = 12345;
        positional_state.commitment_index_digest.reset();
        positional_state.account_registry_snapshot.reset();
        BOOST_REQUIRE(db.Write(std::make_pair(uint8_t{'S'}, uint8_t{0}), positional_state, /*fSync=*/true));
    }

    NullifierSet ns(db_path, 1 << 20, /*memory_only=*/false, /*wipe_data=*/false);
    shielded::ShieldedMerkleTree restored_tree;
    std::vector<uint256> restored_anchor_roots;
    uint256 restored_tip_hash;
    int32_t restored_tip_height{-1};
    CAmount restored_pool_balance{0};
    std::optional<uint256> restored_commitment_index_digest;
    std::optional<shielded::registry::ShieldedAccountRegistryPersistedSnapshot>
        restored_account_registry_snapshot;
    BOOST_REQUIRE(ns.ReadPersistedState(restored_tree,
                                        restored_anchor_roots,
                                        restored_tip_hash,
                                        restored_tip_height,
                                        restored_pool_balance,
                                        restored_commitment_index_digest,
                                        restored_account_registry_snapshot));

    BOOST_CHECK_EQUAL(restored_tree.Size(), 2U);
    BOOST_CHECK_EQUAL(restored_anchor_roots.size(), 2U);
    BOOST_CHECK_EQUAL(restored_tip_height, 211);
    BOOST_CHECK_EQUAL(restored_pool_balance, 12345);
    BOOST_CHECK(!restored_commitment_index_digest.has_value());
    BOOST_CHECK(!restored_account_registry_snapshot.has_value());
}

BOOST_AUTO_TEST_CASE(persisted_shielded_state_roundtrip_reads_positional_state_with_digest_and_snapshot)
{
    const std::filesystem::path db_path = m_args.GetDataDirNet() / "test_nf_persisted_state_positional_digest_snapshot";
    RegistryPayloadStoreGuard payload_store_guard(
        m_args.GetDataDirNet() / "test_nf_persisted_state_positional_digest_snapshot_registry_payloads");
    auto account_registry =
        shielded::registry::ShieldedAccountRegistryState::WithConfiguredPayloadStore();
    const auto account_a = test::shielded::MakeDeterministicCompactPublicAccount(/*seed=*/0xA1, /*value=*/5100);
    const auto account_b = test::shielded::MakeDeterministicCompactPublicAccount(/*seed=*/0xA2, /*value=*/5200);
    const std::vector<shielded::registry::ShieldedAccountLeaf> leaf_payloads{
        *test::shielded::BuildDirectAccountLeaf(
            smile2::ComputeCompactPublicAccountHash(account_a),
            account_a),
        *test::shielded::BuildDirectAccountLeaf(
            smile2::ComputeCompactPublicAccountHash(account_b),
            account_b),
    };
    BOOST_REQUIRE(account_registry.Append(
        Span<const shielded::registry::ShieldedAccountLeaf>{leaf_payloads.data(), leaf_payloads.size()}));
    const auto snapshot = account_registry.ExportSnapshot();
    BOOST_REQUIRE(snapshot.IsValid());

    shielded::ShieldedMerkleTree tree;
    tree.Append(GetRandHash());
    tree.Append(GetRandHash());

    {
        CDBWrapper db({.path = db_path, .cache_bytes = 1 << 20, .memory_only = false, .wipe_data = true, .obfuscate = true});

        PositionalShieldedStateDisk positional_state;
        positional_state.tree = tree;
        positional_state.anchor_roots = {tree.Root(), GetRandHash()};
        positional_state.tip_hash = GetRandHash();
        positional_state.tip_height = 377;
        positional_state.pool_balance = 54321;
        positional_state.commitment_index_digest = tree.CommitmentIndexDigest();
        positional_state.account_registry_snapshot = snapshot;
        BOOST_REQUIRE(db.Write(std::make_pair(uint8_t{'S'}, uint8_t{0}), positional_state, /*fSync=*/true));
    }

    NullifierSet ns(db_path, 1 << 20, /*memory_only=*/false, /*wipe_data=*/false);
    shielded::ShieldedMerkleTree restored_tree;
    std::vector<uint256> restored_anchor_roots;
    uint256 restored_tip_hash;
    int32_t restored_tip_height{-1};
    CAmount restored_pool_balance{0};
    std::optional<uint256> restored_commitment_index_digest;
    std::optional<shielded::registry::ShieldedAccountRegistryPersistedSnapshot>
        restored_account_registry_snapshot;
    BOOST_REQUIRE(ns.ReadPersistedState(restored_tree,
                                        restored_anchor_roots,
                                        restored_tip_hash,
                                        restored_tip_height,
                                        restored_pool_balance,
                                        restored_commitment_index_digest,
                                        restored_account_registry_snapshot));

    BOOST_CHECK_EQUAL(restored_tree.Size(), tree.Size());
    BOOST_CHECK_EQUAL(restored_tip_height, 377);
    BOOST_CHECK_EQUAL(restored_pool_balance, 54321);
    BOOST_REQUIRE(restored_commitment_index_digest.has_value());
    BOOST_CHECK_EQUAL(*restored_commitment_index_digest, *tree.CommitmentIndexDigest());
    BOOST_REQUIRE(restored_account_registry_snapshot.has_value());
    const auto restored_account_registry =
        shielded::registry::ShieldedAccountRegistryState::RestorePersisted(
            *restored_account_registry_snapshot);
    BOOST_REQUIRE(restored_account_registry.has_value());
    BOOST_CHECK_EQUAL(restored_account_registry->Size(), account_registry.Size());
    BOOST_CHECK_EQUAL(restored_account_registry->Root(), account_registry.Root());
}

BOOST_AUTO_TEST_CASE(nullifier_negative_cache_is_invalidated_by_insert)
{
    NullifierSet ns(m_args.GetDataDirNet() / "test_nf_negative_cache", 1 << 20, /*memory_only=*/false, /*wipe_data=*/true);
    const Nullifier nf = GetRandHash();

    BOOST_CHECK(!ns.Contains(nf));
    BOOST_CHECK(!ns.Contains(nf));
    BOOST_CHECK(ns.Insert({nf}));
    BOOST_CHECK(ns.Contains(nf));
}

BOOST_AUTO_TEST_CASE(settlement_anchor_negative_cache_is_invalidated_by_insert)
{
    NullifierSet ns(m_args.GetDataDirNet() / "test_nf_anchor_negative_cache", 1 << 20, /*memory_only=*/false, /*wipe_data=*/true);
    const uint256 anchor = GetRandHash();
    const ConfirmedSettlementAnchorState anchor_state{anchor, /*created_height=*/440};

    BOOST_CHECK(!ns.ContainsSettlementAnchor(anchor));
    BOOST_CHECK(!ns.ContainsSettlementAnchor(anchor));
    BOOST_CHECK(!ns.GetSettlementAnchorState(anchor).has_value());
    BOOST_CHECK(ns.InsertSettlementAnchors({anchor_state}));
    BOOST_CHECK(ns.ContainsSettlementAnchor(anchor));
    BOOST_REQUIRE(ns.GetSettlementAnchorState(anchor).has_value());
    BOOST_CHECK_EQUAL(ns.GetSettlementAnchorState(anchor)->created_height, anchor_state.created_height);
}

BOOST_AUTO_TEST_CASE(netting_manifest_negative_cache_is_invalidated_by_insert)
{
    NullifierSet ns(m_args.GetDataDirNet() / "test_nf_manifest_negative_cache", 1 << 20, /*memory_only=*/false, /*wipe_data=*/true);
    const uint256 manifest_id = GetRandHash();
    const ConfirmedNettingManifestState manifest_state{
        manifest_id,
        /*created_height=*/440,
        /*settlement_window=*/720};

    BOOST_CHECK(!ns.ContainsNettingManifest(manifest_id));
    BOOST_CHECK(!ns.GetNettingManifestState(manifest_id).has_value());
    BOOST_CHECK(ns.InsertNettingManifests({manifest_state}));
    BOOST_CHECK(ns.ContainsNettingManifest(manifest_id));
    const auto restored = ns.GetNettingManifestState(manifest_id);
    BOOST_REQUIRE(restored.has_value());
    BOOST_CHECK_EQUAL(restored->created_height, manifest_state.created_height);
    BOOST_CHECK_EQUAL(restored->settlement_window, manifest_state.settlement_window);
}

BOOST_AUTO_TEST_CASE(shielded_mutation_marker_roundtrip_and_clear)
{
    NullifierSet ns(m_args.GetDataDirNet() / "test_nf_mutation_marker", 1 << 20, /*memory_only=*/false, /*wipe_data=*/true);
    shielded::ShieldedMerkleTree prepared_tree;
    const auto prepared_digest = prepared_tree.CommitmentIndexDigest();
    BOOST_REQUIRE(prepared_digest.has_value());
    shielded::registry::ShieldedAccountRegistryPersistedSnapshot prepared_registry_snapshot;
    BOOST_REQUIRE(prepared_registry_snapshot.IsValid());

    ShieldedStateMutationMarker marker;
    marker.version = ShieldedStateMutationMarker::PREPARED_TRANSITION_VERSION;
    marker.target_tip_hash = GetRandHash();
    marker.target_tip_height = 61'000;
    marker.source_tip_hash = GetRandHash();
    marker.source_tip_height = 60'999;
    marker.prepared_target_snapshot.tree = prepared_tree;
    marker.prepared_target_snapshot.pool_balance = 42;
    marker.prepared_target_snapshot.commitment_index_digest = *prepared_digest;
    marker.prepared_target_snapshot.account_registry_snapshot = prepared_registry_snapshot;

    BOOST_CHECK(!ns.ReadMutationMarker().has_value());
    BOOST_CHECK(ns.WriteMutationMarker(marker));
    const auto restored = ns.ReadMutationMarker();
    BOOST_REQUIRE(restored.has_value());
    BOOST_CHECK_EQUAL(restored->version, marker.version);
    BOOST_CHECK_EQUAL(restored->source_tip_hash, marker.source_tip_hash);
    BOOST_CHECK_EQUAL(restored->source_tip_height, marker.source_tip_height);
    BOOST_CHECK_EQUAL(restored->target_tip_hash, marker.target_tip_hash);
    BOOST_CHECK_EQUAL(restored->target_tip_height, marker.target_tip_height);
    BOOST_CHECK(restored->IsPreparedTransitionJournal());
    BOOST_CHECK_EQUAL(restored->prepared_target_snapshot.pool_balance,
                      marker.prepared_target_snapshot.pool_balance);
    BOOST_CHECK_EQUAL(restored->prepared_target_snapshot.commitment_index_digest,
                      marker.prepared_target_snapshot.commitment_index_digest);
    BOOST_CHECK_EQUAL(restored->prepared_target_snapshot.account_registry_snapshot.entries.size(),
                      marker.prepared_target_snapshot.account_registry_snapshot.entries.size());
    BOOST_CHECK(ns.ClearMutationMarker());
    BOOST_CHECK(!ns.ReadMutationMarker().has_value());
}

BOOST_AUTO_TEST_CASE(shielded_mutation_marker_invalid_payload_forces_recovery_sentinel)
{
    const std::filesystem::path db_path = m_args.GetDataDirNet() / "test_nf_mutation_marker_invalid";
    {
        NullifierSet ns(db_path, 1 << 20, /*memory_only=*/false, /*wipe_data=*/true);
        ShieldedStateMutationMarker marker;
        marker.version = ShieldedStateMutationMarker::LEGACY_VERSION;
        marker.target_tip_hash = GetRandHash();
        marker.target_tip_height = 12;
        BOOST_CHECK(ns.WriteMutationMarker(marker));
    }

    {
        CDBWrapper db({.path = db_path, .cache_bytes = 1 << 20, .memory_only = false, .wipe_data = false, .obfuscate = true});
        BOOST_REQUIRE(db.Write(std::make_pair(uint8_t{'J'}, uint8_t{0}), std::vector<unsigned char>{0x00}, /*fSync=*/true));
    }

    NullifierSet reopened(db_path, 1 << 20, /*memory_only=*/false, /*wipe_data=*/false);
    const auto marker = reopened.ReadMutationMarker();
    BOOST_REQUIRE(marker.has_value());
    BOOST_CHECK(marker->IsValid());
    BOOST_CHECK(marker->target_tip_hash.IsNull());
    BOOST_CHECK_EQUAL(marker->target_tip_height, -1);
}

BOOST_AUTO_TEST_SUITE_END()
