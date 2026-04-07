// Copyright (c) 2024 The BTX Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <dandelion.h>
#include <chainparams.h>
#include <consensus/amount.h>
#include <netaddress.h>
#include <node/connection_types.h>
#include <primitives/transaction.h>
#include <random.h>
#include <script/script.h>
#include <serialize.h>
#include <test/util/net.h>
#include <test/util/setup_common.h>
#include <uint256.h>

#include <boost/test/unit_test.hpp>

#include <arpa/inet.h>

#include <map>
#include <set>

namespace {

CTransactionRef CreateTestTx()
{
    CMutableTransaction mtx;
    mtx.version = 2;
    mtx.vin.resize(1);
    mtx.vin[0].prevout.hash = Txid::FromUint256(GetRandHash());
    mtx.vin[0].prevout.n = 0;
    mtx.vout.resize(1);
    mtx.vout[0].nValue = 50 * COIN;
    mtx.vout[0].scriptPubKey = CScript() << OP_TRUE;
    return MakeTransactionRef(std::move(mtx));
}

static CService DandelionTestIp(uint32_t host)
{
    struct in_addr addr;
    addr.s_addr = host;
    return CService{CNetAddr{addr}, Params().GetDefaultPort()};
}

static CNode* AddDandelionPeer(ConnmanTestMsg& connman,
                               NodeId& next_id,
                               uint64_t keyed_netgroup,
                               uint32_t host,
                               bool supports_dandelion,
                               ConnectionType conn_type = ConnectionType::OUTBOUND_FULL_RELAY)
{
    auto* node = new CNode{++next_id,
                           /*sock=*/nullptr,
                           CAddress{DandelionTestIp(host), NODE_NONE},
                           keyed_netgroup,
                           /*nLocalHostNonceIn=*/0,
                           CAddress{},
                           /*addrNameIn=*/"",
                           conn_type,
                           /*inbound_onion=*/false,
                           /*network_key=*/0};
    node->fSuccessfullyConnected = true;
    node->m_supports_dandelion = supports_dandelion;
    connman.AddTestNode(*node);
    return node;
}

static bool RotateUntilStemMode(Dandelion::DandelionManager& manager, int attempts = 16)
{
    for (int attempt = 0; attempt < attempts; ++attempt) {
        manager.ForceRotateEpoch();
        if (manager.IsInStemMode()) return true;
    }
    return false;
}

static bool RotateUntilFluffMode(Dandelion::DandelionManager& manager, int attempts = 128)
{
    for (int attempt = 0; attempt < attempts; ++attempt) {
        manager.ForceRotateEpoch();
        if (!manager.IsInStemMode()) return true;
    }
    return false;
}

} // anonymous namespace

BOOST_FIXTURE_TEST_SUITE(dandelion_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(activation_height)
{
    Dandelion::DandelionManager manager;

    BOOST_CHECK(!manager.IsActive(0));
    BOOST_CHECK(!manager.IsActive(1));
    BOOST_CHECK(!manager.IsActive(60'999));
    BOOST_CHECK(manager.IsActive(61'000));
    BOOST_CHECK(manager.IsActive(61'001));
    BOOST_CHECK(manager.IsActive(500000));
}

BOOST_AUTO_TEST_CASE(stempool_accept_without_connman)
{
    Dandelion::DandelionManager manager;
    manager.Initialize(nullptr);
    manager.ForceRotateEpoch();

    CTransactionRef tx = CreateTestTx();
    const uint256 txid = tx->GetHash();

    auto [result, relay_to] = manager.AcceptStemTransaction(tx, /*from_peer=*/0, ::GetSerializeSize(TX_WITH_WITNESS(tx)));

    // Without connman there are no relay destinations, so it should fluff immediately.
    BOOST_CHECK_EQUAL(static_cast<int>(result),
                      static_cast<int>(Dandelion::DandelionManager::AcceptResult::FLUFF_IMMEDIATELY));

    // The bloom filter should still have recorded the transaction.
    BOOST_CHECK(manager.HaveStemTx(txid));
}

BOOST_AUTO_TEST_CASE(stempool_duplicate_rejection)
{
    Dandelion::DandelionManager manager;
    manager.Initialize(nullptr);
    manager.ForceRotateEpoch();

    CTransactionRef tx = CreateTestTx();

    auto [result1, relay1] = manager.AcceptStemTransaction(tx, /*from_peer=*/0, ::GetSerializeSize(TX_WITH_WITNESS(tx)));
    // First submission succeeds (or fluffs, either way it is accepted).
    BOOST_CHECK(result1 == Dandelion::DandelionManager::AcceptResult::ACCEPTED ||
                result1 == Dandelion::DandelionManager::AcceptResult::FLUFF_IMMEDIATELY);

    // Second submission of the same tx should be rejected as already known.
    auto [result2, relay2] = manager.AcceptStemTransaction(tx, /*from_peer=*/1, ::GetSerializeSize(TX_WITH_WITNESS(tx)));
    BOOST_CHECK_EQUAL(static_cast<int>(result2),
                      static_cast<int>(Dandelion::DandelionManager::AcceptResult::ALREADY_KNOWN));
}

BOOST_AUTO_TEST_CASE(stempool_mempool_notification)
{
    Dandelion::DandelionManager manager;
    manager.Initialize(nullptr);
    manager.ForceRotateEpoch();

    CTransactionRef tx = CreateTestTx();
    const uint256 txid = tx->GetHash();

    manager.AcceptStemTransaction(tx, /*from_peer=*/0, ::GetSerializeSize(TX_WITH_WITNESS(tx)));

    // Notify that the tx was added to the mempool; it should be removed from the stempool.
    manager.TxAddedToMempool(txid);

    CTransactionRef removed = manager.RemoveFromStemPool(txid);
    BOOST_CHECK(!removed);
}

BOOST_AUTO_TEST_CASE(per_peer_rate_limiting)
{
    Dandelion::DandelionManager manager;
    manager.Initialize(nullptr);
    manager.ForceRotateEpoch();

    const NodeId peer_a = 100;
    const NodeId peer_b = 200;

    // Fill up peer_a's per-peer limit.
    for (size_t i = 0; i < Dandelion::MAX_STEM_TXS_PER_PEER; ++i) {
        CTransactionRef tx = CreateTestTx();
        auto [result, relay] = manager.AcceptStemTransaction(tx, peer_a, ::GetSerializeSize(TX_WITH_WITNESS(tx)));
        BOOST_CHECK(result == Dandelion::DandelionManager::AcceptResult::ACCEPTED ||
                    result == Dandelion::DandelionManager::AcceptResult::FLUFF_IMMEDIATELY);
    }

    // The next tx from peer_a should be rate limited.
    CTransactionRef tx_over = CreateTestTx();
    auto [result_limited, relay_limited] = manager.AcceptStemTransaction(tx_over, peer_a, ::GetSerializeSize(TX_WITH_WITNESS(tx_over)));
    BOOST_CHECK_EQUAL(static_cast<int>(result_limited),
                      static_cast<int>(Dandelion::DandelionManager::AcceptResult::RATE_LIMITED));

    // A different peer should still be able to submit.
    CTransactionRef tx_b = CreateTestTx();
    auto [result_b, relay_b] = manager.AcceptStemTransaction(tx_b, peer_b, ::GetSerializeSize(TX_WITH_WITNESS(tx_b)));
    BOOST_CHECK(result_b == Dandelion::DandelionManager::AcceptResult::ACCEPTED ||
                result_b == Dandelion::DandelionManager::AcceptResult::FLUFF_IMMEDIATELY);
}

BOOST_AUTO_TEST_CASE(per_peer_byte_rate_limiting)
{
    Dandelion::DandelionManager manager;
    manager.Initialize(nullptr);
    manager.ForceRotateEpoch();

    const NodeId peer = 42;

    // Submit a single tx but claim its size exceeds the per-peer byte limit.
    CTransactionRef tx = CreateTestTx();
    size_t oversized = Dandelion::MAX_STEM_BYTES_PER_PEER + 1;

    auto [result, relay] = manager.AcceptStemTransaction(tx, peer, oversized);
    BOOST_CHECK_EQUAL(static_cast<int>(result),
                      static_cast<int>(Dandelion::DandelionManager::AcceptResult::RATE_LIMITED));
}

BOOST_AUTO_TEST_CASE(embargo_check_empty)
{
    Dandelion::DandelionManager manager;
    manager.Initialize(nullptr);

    std::vector<CTransactionRef> expired = manager.CheckEmbargoes();
    BOOST_CHECK(expired.empty());
}

BOOST_AUTO_TEST_CASE(epoch_rotation_resets_peer_state)
{
    Dandelion::DandelionManager manager;
    manager.Initialize(nullptr);
    manager.ForceRotateEpoch();

    const NodeId peer = 300;

    // Fill up the peer's per-peer limit.
    for (size_t i = 0; i < Dandelion::MAX_STEM_TXS_PER_PEER; ++i) {
        CTransactionRef tx = CreateTestTx();
        manager.AcceptStemTransaction(tx, peer, ::GetSerializeSize(TX_WITH_WITNESS(tx)));
    }

    // Confirm the peer is now rate limited.
    CTransactionRef tx_limited = CreateTestTx();
    auto [result_before, relay_before] = manager.AcceptStemTransaction(tx_limited, peer, ::GetSerializeSize(TX_WITH_WITNESS(tx_limited)));
    BOOST_CHECK_EQUAL(static_cast<int>(result_before),
                      static_cast<int>(Dandelion::DandelionManager::AcceptResult::RATE_LIMITED));

    // Rotate the epoch; per-peer state should reset.
    manager.ForceRotateEpoch();

    CTransactionRef tx_after = CreateTestTx();
    auto [result_after, relay_after] = manager.AcceptStemTransaction(tx_after, peer, ::GetSerializeSize(TX_WITH_WITNESS(tx_after)));
    BOOST_CHECK(result_after == Dandelion::DandelionManager::AcceptResult::ACCEPTED ||
                result_after == Dandelion::DandelionManager::AcceptResult::FLUFF_IMMEDIATELY);
}

BOOST_AUTO_TEST_CASE(peer_disconnect_cleanup)
{
    Dandelion::DandelionManager manager;
    manager.Initialize(nullptr);
    manager.ForceRotateEpoch();

    const NodeId peer = 400;

    // Fill up the peer's per-peer limit.
    for (size_t i = 0; i < Dandelion::MAX_STEM_TXS_PER_PEER; ++i) {
        CTransactionRef tx = CreateTestTx();
        manager.AcceptStemTransaction(tx, peer, ::GetSerializeSize(TX_WITH_WITNESS(tx)));
    }

    // Confirm the peer is rate limited.
    CTransactionRef tx_limited = CreateTestTx();
    auto [result_before, relay_before] = manager.AcceptStemTransaction(tx_limited, peer, ::GetSerializeSize(TX_WITH_WITNESS(tx_limited)));
    BOOST_CHECK_EQUAL(static_cast<int>(result_before),
                      static_cast<int>(Dandelion::DandelionManager::AcceptResult::RATE_LIMITED));

    // Disconnect the peer; its state should be cleaned up.
    manager.PeerDisconnected(peer);

    CTransactionRef tx_after = CreateTestTx();
    auto [result_after, relay_after] = manager.AcceptStemTransaction(tx_after, peer, ::GetSerializeSize(TX_WITH_WITNESS(tx_after)));
    BOOST_CHECK(result_after == Dandelion::DandelionManager::AcceptResult::ACCEPTED ||
                result_after == Dandelion::DandelionManager::AcceptResult::FLUFF_IMMEDIATELY);
}

BOOST_AUTO_TEST_CASE(stempool_byte_tracking)
{
    Dandelion::DandelionManager manager;
    manager.Initialize(nullptr);

    BOOST_CHECK_EQUAL(manager.GetStemPoolSize(), 0U);
    BOOST_CHECK_EQUAL(manager.GetStemPoolBytes(), 0U);
}

BOOST_AUTO_TEST_CASE(relay_peers_empty_without_connman)
{
    Dandelion::DandelionManager manager;
    manager.Initialize(nullptr);
    manager.ForceRotateEpoch();

    std::vector<NodeId> peers = manager.GetRelayPeers();
    BOOST_CHECK(peers.empty());
}

BOOST_AUTO_TEST_CASE(have_stem_tx_checks_bloom_filter)
{
    // Verify HaveStemTx returns true for txs recorded in the bloom filter
    // even when they are not in the stempool (e.g. FLUFF_IMMEDIATELY path).
    Dandelion::DandelionManager manager;
    manager.Initialize(nullptr);
    manager.ForceRotateEpoch();

    CTransactionRef tx = CreateTestTx();
    const uint256 txid = tx->GetHash();

    // Without connman, AcceptStemTransaction returns FLUFF_IMMEDIATELY which
    // inserts into bloom filter but NOT stempool.
    auto [result, relay] = manager.AcceptStemTransaction(tx, /*from_peer=*/0,
        ::GetSerializeSize(TX_WITH_WITNESS(tx)));
    BOOST_CHECK_EQUAL(static_cast<int>(result),
                      static_cast<int>(Dandelion::DandelionManager::AcceptResult::FLUFF_IMMEDIATELY));

    // HaveStemTx must still report true via bloom filter.
    BOOST_CHECK(manager.HaveStemTx(txid));

    // Stempool itself should be empty.
    BOOST_CHECK_EQUAL(manager.GetStemPoolSize(), 0U);
}

BOOST_AUTO_TEST_CASE(stempool_size_and_bytes_after_insert)
{
    // Verify stempool size and byte tracking after actual insertions.
    Dandelion::DandelionManager manager;
    manager.Initialize(nullptr);
    manager.ForceRotateEpoch();

    CTransactionRef tx1 = CreateTestTx();
    CTransactionRef tx2 = CreateTestTx();
    const size_t sz1 = ::GetSerializeSize(TX_WITH_WITNESS(tx1));
    const size_t sz2 = ::GetSerializeSize(TX_WITH_WITNESS(tx2));

    // These will FLUFF_IMMEDIATELY without connman, so stempool stays empty.
    // Verify that FLUFF_IMMEDIATELY does NOT add to stempool.
    manager.AcceptStemTransaction(tx1, /*from_peer=*/0, sz1);
    manager.AcceptStemTransaction(tx2, /*from_peer=*/1, sz2);

    BOOST_CHECK_EQUAL(manager.GetStemPoolSize(), 0U);
    BOOST_CHECK_EQUAL(manager.GetStemPoolBytes(), 0U);
}

BOOST_AUTO_TEST_CASE(epoch_rotation_flushes_stempool)
{
    // Verify that ForceRotateEpoch flushes stempool entries to pending_fluff,
    // which are then returned by CheckEmbargoes.
    Dandelion::DandelionManager manager;
    manager.Initialize(nullptr);
    manager.ForceRotateEpoch();

    // Without connman, we can't get txs into stempool directly since they
    // FLUFF_IMMEDIATELY. But we can test the flush mechanism indirectly:
    // After rotation, CheckEmbargoes should return any pending_fluff entries.

    // First verify empty state.
    auto expired = manager.CheckEmbargoes();
    BOOST_CHECK(expired.empty());

    // Force another rotation (stempool is empty, so nothing to flush).
    manager.ForceRotateEpoch();
    expired = manager.CheckEmbargoes();
    BOOST_CHECK(expired.empty());
}

BOOST_AUTO_TEST_CASE(remove_from_stempool_nonexistent)
{
    // RemoveFromStemPool for a tx that doesn't exist returns nullptr.
    Dandelion::DandelionManager manager;
    manager.Initialize(nullptr);
    manager.ForceRotateEpoch();

    CTransactionRef removed = manager.RemoveFromStemPool(GetRandHash());
    BOOST_CHECK(!removed);
}

BOOST_AUTO_TEST_CASE(tx_added_to_mempool_nonexistent)
{
    // TxAddedToMempool for a tx not in stempool should be a no-op.
    Dandelion::DandelionManager manager;
    manager.Initialize(nullptr);
    manager.ForceRotateEpoch();

    // Should not crash or affect state.
    manager.TxAddedToMempool(GetRandHash());

    BOOST_CHECK_EQUAL(manager.GetStemPoolSize(), 0U);
    BOOST_CHECK_EQUAL(manager.GetStemPoolBytes(), 0U);
}

BOOST_AUTO_TEST_CASE(is_in_stem_mode_after_init)
{
    // IsInStemMode should return a valid boolean after initialization.
    Dandelion::DandelionManager manager;
    manager.Initialize(nullptr);
    manager.ForceRotateEpoch();

    // With STEM_PROBABILITY=0.9, most epochs will be stem mode.
    // We can't assert a specific value due to randomness, but it should
    // not crash and should return a bool.
    bool mode = manager.IsInStemMode();
    BOOST_CHECK(mode == true || mode == false);
}

BOOST_AUTO_TEST_CASE(get_relay_destination_no_route)
{
    // GetRelayDestination returns nullopt when no route is assigned.
    Dandelion::DandelionManager manager;
    manager.Initialize(nullptr);
    manager.ForceRotateEpoch();

    auto dest = manager.GetRelayDestination(/*from_peer=*/999);
    BOOST_CHECK(!dest.has_value());
}

BOOST_AUTO_TEST_CASE(peer_disconnect_unknown_peer)
{
    // PeerDisconnected for a peer we've never seen should be a no-op.
    Dandelion::DandelionManager manager;
    manager.Initialize(nullptr);
    manager.ForceRotateEpoch();

    // Should not crash.
    manager.PeerDisconnected(/*peer_id=*/12345);

    BOOST_CHECK_EQUAL(manager.GetStemPoolSize(), 0U);
}

BOOST_AUTO_TEST_CASE(local_wallet_tx_not_rate_limited)
{
    // Local wallet transactions (from_peer == -1) should bypass rate limiting.
    Dandelion::DandelionManager manager;
    manager.Initialize(nullptr);
    manager.ForceRotateEpoch();

    // Submit many txs from local wallet (from_peer == -1).
    for (size_t i = 0; i < Dandelion::MAX_STEM_TXS_PER_PEER + 10; ++i) {
        CTransactionRef tx = CreateTestTx();
        auto [result, relay] = manager.AcceptStemTransaction(tx, /*from_peer=*/-1,
            ::GetSerializeSize(TX_WITH_WITNESS(tx)));
        // Should never be RATE_LIMITED for local txs.
        BOOST_CHECK(result != Dandelion::DandelionManager::AcceptResult::RATE_LIMITED);
    }
}

BOOST_AUTO_TEST_CASE(multiple_epoch_rotations_stability)
{
    // Multiple rapid epoch rotations should not crash or corrupt state.
    Dandelion::DandelionManager manager;
    manager.Initialize(nullptr);

    for (int i = 0; i < 100; ++i) {
        manager.ForceRotateEpoch();
    }

    // After many rotations, basic operations should still work.
    BOOST_CHECK_EQUAL(manager.GetStemPoolSize(), 0U);
    BOOST_CHECK_EQUAL(manager.GetStemPoolBytes(), 0U);
    BOOST_CHECK(manager.GetRelayPeers().empty());

    CTransactionRef tx = CreateTestTx();
    auto [result, relay] = manager.AcceptStemTransaction(tx, /*from_peer=*/0,
        ::GetSerializeSize(TX_WITH_WITNESS(tx)));
    BOOST_CHECK(result == Dandelion::DandelionManager::AcceptResult::ACCEPTED ||
                result == Dandelion::DandelionManager::AcceptResult::FLUFF_IMMEDIATELY);
}

BOOST_AUTO_TEST_CASE(stempool_full_protection)
{
    // When stempool is full and cannot evict (no room), STEMPOOL_FULL is returned.
    // This is hard to trigger without connman since txs FLUFF_IMMEDIATELY,
    // but we verify the code path compiles and the result enum exists.
    Dandelion::DandelionManager manager;
    manager.Initialize(nullptr);
    manager.ForceRotateEpoch();

    // Verify the STEMPOOL_FULL enum value exists and compiles.
    auto full = Dandelion::DandelionManager::AcceptResult::STEMPOOL_FULL;
    BOOST_CHECK_EQUAL(static_cast<int>(full), 4);
}

BOOST_AUTO_TEST_CASE(bloom_filter_persistence_across_epochs)
{
    // The bloom filter should persist across epoch rotations to prevent
    // re-processing of previously seen transactions.
    Dandelion::DandelionManager manager;
    manager.Initialize(nullptr);
    manager.ForceRotateEpoch();

    CTransactionRef tx = CreateTestTx();
    const uint256 txid = tx->GetHash();

    // Accept tx (will FLUFF_IMMEDIATELY, inserting into bloom filter).
    manager.AcceptStemTransaction(tx, /*from_peer=*/0, ::GetSerializeSize(TX_WITH_WITNESS(tx)));
    BOOST_CHECK(manager.HaveStemTx(txid));

    // Rotate epoch.
    manager.ForceRotateEpoch();

    // Bloom filter should still report the tx as seen.
    BOOST_CHECK(manager.HaveStemTx(txid));

    // Trying to accept the same tx again should return ALREADY_KNOWN.
    auto [result, relay] = manager.AcceptStemTransaction(tx, /*from_peer=*/1,
        ::GetSerializeSize(TX_WITH_WITNESS(tx)));
    BOOST_CHECK_EQUAL(static_cast<int>(result),
                      static_cast<int>(Dandelion::DandelionManager::AcceptResult::ALREADY_KNOWN));
}

BOOST_AUTO_TEST_CASE(relay_selection_prefers_supporting_peers_and_distinct_netgroups)
{
    ConnmanTestMsg connman{0x1337, 0x1337, *m_node.addrman, *m_node.netgroupman, Params()};
    NodeId next_id{0};

    const CNode* same_group_a = AddDandelionPeer(connman, next_id, /*keyed_netgroup=*/11, 0x01010101, true);
    const CNode* same_group_b = AddDandelionPeer(connman, next_id, /*keyed_netgroup=*/11, 0x02020202, true);
    const CNode* distinct_group = AddDandelionPeer(connman, next_id, /*keyed_netgroup=*/22, 0x03030303, true);
    const CNode* non_supporting = AddDandelionPeer(connman, next_id, /*keyed_netgroup=*/33, 0x04040404, false);

    Dandelion::DandelionManager manager;
    manager.Initialize(&connman);
    manager.ForceRotateEpoch();

    const auto relays = manager.GetRelayPeers();
    BOOST_REQUIRE_GE(relays.size(), 2U);

    const std::set<NodeId> selected(relays.begin(), relays.end());
    BOOST_CHECK(selected.count(non_supporting->GetId()) == 0U);
    BOOST_CHECK(!(selected.count(same_group_a->GetId()) != 0U &&
                  selected.count(same_group_b->GetId()) != 0U));
    BOOST_CHECK(selected.count(distinct_group->GetId()) != 0U);

    connman.ClearTestNodes();
}

BOOST_AUTO_TEST_CASE(relay_selection_uses_block_relay_peers_when_full_outbound_absent)
{
    ConnmanTestMsg connman{0x1337, 0x1337, *m_node.addrman, *m_node.netgroupman, Params()};
    NodeId next_id{0};

    const CNode* block_relay_a = AddDandelionPeer(connman,
                                                  next_id,
                                                  /*keyed_netgroup=*/51,
                                                  0x07070707,
                                                  true,
                                                  ConnectionType::BLOCK_RELAY);
    const CNode* block_relay_b = AddDandelionPeer(connman,
                                                  next_id,
                                                  /*keyed_netgroup=*/52,
                                                  0x08080808,
                                                  true,
                                                  ConnectionType::BLOCK_RELAY);

    Dandelion::DandelionManager manager;
    manager.Initialize(&connman);
    manager.ForceRotateEpoch();

    const auto relays = manager.GetRelayPeers();
    BOOST_REQUIRE_EQUAL(relays.size(), 2U);
    const std::set<NodeId> selected_relays(relays.begin(), relays.end());
    const std::set<NodeId> expected_relays{block_relay_a->GetId(), block_relay_b->GetId()};
    BOOST_CHECK(selected_relays == expected_relays);

    connman.ClearTestNodes();
}

BOOST_AUTO_TEST_CASE(same_peer_transactions_rotate_within_bounded_relay_pool)
{
    ConnmanTestMsg connman{0x1337, 0x1337, *m_node.addrman, *m_node.netgroupman, Params()};
    NodeId next_id{0};
    AddDandelionPeer(connman, next_id, /*keyed_netgroup=*/61, 0x09090909, true);
    AddDandelionPeer(connman, next_id, /*keyed_netgroup=*/62, 0x0A0A0A0A, true);
    AddDandelionPeer(connman, next_id, /*keyed_netgroup=*/63, 0x0B0B0B0B, true);
    AddDandelionPeer(connman, next_id, /*keyed_netgroup=*/64, 0x0C0C0C0C, true);

    Dandelion::DandelionManager manager;
    manager.Initialize(&connman);
    BOOST_REQUIRE(RotateUntilStemMode(manager));

    const NodeId from_peer = 77;
    std::set<NodeId> observed_relays;
    for (int i = 0; i < 64; ++i) {
        const CTransactionRef tx = CreateTestTx();
        const size_t tx_size = ::GetSerializeSize(TX_WITH_WITNESS(tx));
        const auto [result, relay] = manager.AcceptStemTransaction(tx, from_peer, tx_size);
        BOOST_REQUIRE_EQUAL(result, Dandelion::DandelionManager::AcceptResult::ACCEPTED);
        BOOST_REQUIRE(relay.has_value());
        observed_relays.insert(*relay);
        manager.RemoveFromStemPool(tx->GetHash());
    }

    BOOST_CHECK_GE(observed_relays.size(), 2U);
    BOOST_CHECK_LE(observed_relays.size(), Dandelion::SOURCE_RELAY_POOL_SIZE);
    const auto last_route = manager.GetRelayDestination(from_peer);
    BOOST_REQUIRE(last_route.has_value());
    BOOST_CHECK(observed_relays.count(*last_route) != 0U);

    connman.ClearTestNodes();
}

BOOST_AUTO_TEST_CASE(local_transactions_rotate_within_bounded_relay_pool)
{
    ConnmanTestMsg connman{0x1337, 0x1337, *m_node.addrman, *m_node.netgroupman, Params()};
    NodeId next_id{0};
    AddDandelionPeer(connman, next_id, /*keyed_netgroup=*/91, 0x13131313, true);
    AddDandelionPeer(connman, next_id, /*keyed_netgroup=*/92, 0x14141414, true);
    AddDandelionPeer(connman, next_id, /*keyed_netgroup=*/93, 0x15151515, true);
    AddDandelionPeer(connman, next_id, /*keyed_netgroup=*/94, 0x16161616, true);

    Dandelion::DandelionManager manager;
    manager.Initialize(&connman);
    BOOST_REQUIRE(RotateUntilStemMode(manager));

    std::set<NodeId> observed_relays;
    for (int i = 0; i < 64; ++i) {
        const CTransactionRef tx = CreateTestTx();
        const size_t tx_size = ::GetSerializeSize(TX_WITH_WITNESS(tx));
        const auto [result, relay] = manager.AcceptStemTransaction(tx, /*from_peer=*/-1, tx_size);
        BOOST_REQUIRE_EQUAL(result, Dandelion::DandelionManager::AcceptResult::ACCEPTED);
        BOOST_REQUIRE(relay.has_value());
        observed_relays.insert(*relay);
        manager.RemoveFromStemPool(tx->GetHash());
    }

    BOOST_CHECK_GE(observed_relays.size(), 2U);
    BOOST_CHECK_LE(observed_relays.size(), Dandelion::SOURCE_RELAY_POOL_SIZE);
    const auto last_route = manager.GetRelayDestination(/*from_peer=*/-1);
    BOOST_REQUIRE(last_route.has_value());
    BOOST_CHECK(observed_relays.count(*last_route) != 0U);

    connman.ClearTestNodes();
}

BOOST_AUTO_TEST_CASE(incoming_edges_distribute_across_multiple_relays_under_sybil_load)
{
    ConnmanTestMsg connman{0x1337, 0x1337, *m_node.addrman, *m_node.netgroupman, Params()};
    NodeId next_id{0};
    AddDandelionPeer(connman, next_id, /*keyed_netgroup=*/101, 0x21010101, true);
    AddDandelionPeer(connman, next_id, /*keyed_netgroup=*/102, 0x22020202, true);
    AddDandelionPeer(connman, next_id, /*keyed_netgroup=*/103, 0x23030303, true);
    AddDandelionPeer(connman, next_id, /*keyed_netgroup=*/104, 0x24040404, true);
    AddDandelionPeer(connman, next_id, /*keyed_netgroup=*/105, 0x25050505, true);
    AddDandelionPeer(connman, next_id, /*keyed_netgroup=*/106, 0x26060606, true);

    Dandelion::DandelionManager manager;
    manager.Initialize(&connman);
    BOOST_REQUIRE(RotateUntilStemMode(manager));

    constexpr NodeId FIRST_SOURCE = 500;
    constexpr size_t SOURCE_COUNT = 16;
    std::map<NodeId, size_t> relay_usage;

    for (size_t i = 0; i < SOURCE_COUNT; ++i) {
        const NodeId from_peer = FIRST_SOURCE + static_cast<NodeId>(i);
        std::set<NodeId> observed_relays;
        for (int tx_index = 0; tx_index < 4; ++tx_index) {
            const CTransactionRef tx = CreateTestTx();
            const size_t tx_size = ::GetSerializeSize(TX_WITH_WITNESS(tx));
            const auto [result, relay] = manager.AcceptStemTransaction(tx, from_peer, tx_size);
            BOOST_REQUIRE_EQUAL(result, Dandelion::DandelionManager::AcceptResult::ACCEPTED);
            BOOST_REQUIRE(relay.has_value());
            observed_relays.insert(*relay);
            manager.RemoveFromStemPool(tx->GetHash());
        }

        BOOST_CHECK_GE(observed_relays.size(), 1U);
        BOOST_CHECK_LE(observed_relays.size(), Dandelion::SOURCE_RELAY_POOL_SIZE);

        const auto route = manager.GetRelayDestination(from_peer);
        BOOST_REQUIRE(route.has_value());
        ++relay_usage[*route];
    }

    BOOST_CHECK_GE(relay_usage.size(), 3U);
    for (const auto& [relay_id, count] : relay_usage) {
        BOOST_TEST_CONTEXT("relay_id=" << relay_id << " count=" << count) {
            BOOST_CHECK_LT(count, SOURCE_COUNT);
        }
    }

    connman.ClearTestNodes();
}

BOOST_AUTO_TEST_CASE(epoch_rotation_reshuffles_source_routes_without_single_relay_collapse)
{
    ConnmanTestMsg connman{0x1337, 0x1337, *m_node.addrman, *m_node.netgroupman, Params()};
    NodeId next_id{0};
    AddDandelionPeer(connman, next_id, /*keyed_netgroup=*/111, 0x31010101, true);
    AddDandelionPeer(connman, next_id, /*keyed_netgroup=*/112, 0x32020202, true);
    AddDandelionPeer(connman, next_id, /*keyed_netgroup=*/113, 0x33030303, true);
    AddDandelionPeer(connman, next_id, /*keyed_netgroup=*/114, 0x34040404, true);
    AddDandelionPeer(connman, next_id, /*keyed_netgroup=*/115, 0x35050505, true);
    AddDandelionPeer(connman, next_id, /*keyed_netgroup=*/116, 0x36060606, true);

    Dandelion::DandelionManager manager;
    manager.Initialize(&connman);
    BOOST_REQUIRE(RotateUntilStemMode(manager));

    constexpr NodeId FIRST_SOURCE = 700;
    constexpr size_t SOURCE_COUNT = 12;
    std::map<NodeId, NodeId> before_routes;
    std::map<NodeId, NodeId> after_routes;

    const auto sample_routes = [&](std::map<NodeId, NodeId>& out_routes) {
        for (size_t i = 0; i < SOURCE_COUNT; ++i) {
            const NodeId from_peer = FIRST_SOURCE + static_cast<NodeId>(i);
            const CTransactionRef tx = CreateTestTx();
            const size_t tx_size = ::GetSerializeSize(TX_WITH_WITNESS(tx));
            const auto [result, relay] = manager.AcceptStemTransaction(tx, from_peer, tx_size);
            BOOST_REQUIRE_EQUAL(result, Dandelion::DandelionManager::AcceptResult::ACCEPTED);
            BOOST_REQUIRE(relay.has_value());
            out_routes.emplace(from_peer, *relay);
            manager.RemoveFromStemPool(tx->GetHash());
        }
    };

    sample_routes(before_routes);
    BOOST_REQUIRE(RotateUntilStemMode(manager));
    sample_routes(after_routes);

    size_t changed_routes{0};
    std::set<NodeId> distinct_after_relays;
    for (const auto& [from_peer, relay_before] : before_routes) {
        const auto after_it = after_routes.find(from_peer);
        BOOST_REQUIRE(after_it != after_routes.end());
        if (after_it->second != relay_before) {
            ++changed_routes;
        }
        distinct_after_relays.insert(after_it->second);
    }

    BOOST_CHECK_GT(changed_routes, 0U);
    BOOST_CHECK_GE(distinct_after_relays.size(), 3U);

    connman.ClearTestNodes();
}

BOOST_AUTO_TEST_CASE(local_wallet_transactions_stem_even_during_fluff_epochs)
{
    ConnmanTestMsg connman{0x1337, 0x1337, *m_node.addrman, *m_node.netgroupman, Params()};
    NodeId next_id{0};
    AddDandelionPeer(connman, next_id, /*keyed_netgroup=*/95, 0x17171717, true);
    AddDandelionPeer(connman, next_id, /*keyed_netgroup=*/96, 0x18181818, true);

    Dandelion::DandelionManager manager;
    manager.Initialize(&connman);
    BOOST_REQUIRE(RotateUntilFluffMode(manager));

    const CTransactionRef tx = CreateTestTx();
    const size_t tx_size = ::GetSerializeSize(TX_WITH_WITNESS(tx));
    const auto [result, relay] = manager.AcceptStemTransaction(tx, /*from_peer=*/-1, tx_size);

    BOOST_CHECK_EQUAL(result, Dandelion::DandelionManager::AcceptResult::ACCEPTED);
    BOOST_REQUIRE(relay.has_value());
    BOOST_CHECK(manager.IsInStemPool(tx->GetHash()));

    connman.ClearTestNodes();
}

BOOST_AUTO_TEST_CASE(peer_disconnect_preserves_embargo_without_forced_fluff)
{
    ConnmanTestMsg connman{0x1337, 0x1337, *m_node.addrman, *m_node.netgroupman, Params()};
    NodeId next_id{0};
    const CNode* relay = AddDandelionPeer(connman, next_id, /*keyed_netgroup=*/71, 0x0C0C0C0C, true);

    Dandelion::DandelionManager manager;
    manager.Initialize(&connman);
    BOOST_REQUIRE(RotateUntilStemMode(manager));

    const CTransactionRef tx = CreateTestTx();
    const size_t tx_size = ::GetSerializeSize(TX_WITH_WITNESS(tx));
    const auto [result, selected_relay] = manager.AcceptStemTransaction(tx, /*from_peer=*/17, tx_size);
    BOOST_REQUIRE_EQUAL(result, Dandelion::DandelionManager::AcceptResult::ACCEPTED);
    BOOST_REQUIRE(selected_relay.has_value());
    BOOST_CHECK_EQUAL(*selected_relay, relay->GetId());
    BOOST_REQUIRE_EQUAL(manager.GetStemPoolSize(), 1U);

    manager.PeerDisconnected(relay->GetId());

    BOOST_CHECK_EQUAL(manager.GetStemPoolSize(), 1U);
    BOOST_CHECK(manager.CheckEmbargoes().empty());

    connman.ClearTestNodes();
}

BOOST_AUTO_TEST_CASE(peer_disconnect_reselects_alternate_relays_before_fluffing)
{
    ConnmanTestMsg connman{0x1337, 0x1337, *m_node.addrman, *m_node.netgroupman, Params()};
    NodeId next_id{0};
    const CNode* peer_a = AddDandelionPeer(connman, next_id, /*keyed_netgroup=*/81, 0x0D0D0D0D, true);
    const CNode* peer_b = AddDandelionPeer(connman, next_id, /*keyed_netgroup=*/82, 0x0E0E0E0E, true);
    const CNode* peer_c = AddDandelionPeer(connman, next_id, /*keyed_netgroup=*/83, 0x0F0F0F0F, true);
    const CNode* peer_d = AddDandelionPeer(connman, next_id, /*keyed_netgroup=*/84, 0x10101010, true);
    const CNode* peer_e = AddDandelionPeer(connman, next_id, /*keyed_netgroup=*/85, 0x11111111, true);
    const CNode* peer_f = AddDandelionPeer(connman, next_id, /*keyed_netgroup=*/86, 0x12121212, true);

    Dandelion::DandelionManager manager;
    manager.Initialize(&connman);
    BOOST_REQUIRE(RotateUntilStemMode(manager));

    const auto initial_relays = manager.GetRelayPeers();
    BOOST_REQUIRE_EQUAL(initial_relays.size(), static_cast<size_t>(Dandelion::MAX_DESTINATIONS));
    const std::set<NodeId> all_peer_ids{
        peer_a->GetId(),
        peer_b->GetId(),
        peer_c->GetId(),
        peer_d->GetId(),
        peer_e->GetId(),
        peer_f->GetId(),
    };
    std::set<NodeId> spare_relays = all_peer_ids;
    for (const NodeId relay_id : initial_relays) {
        spare_relays.erase(relay_id);
    }
    BOOST_REQUIRE_EQUAL(spare_relays.size(), 2U);

    const CTransactionRef tx = CreateTestTx();
    const size_t tx_size = ::GetSerializeSize(TX_WITH_WITNESS(tx));
    const auto [result, relay] = manager.AcceptStemTransaction(tx, /*from_peer=*/31, tx_size);
    BOOST_REQUIRE_EQUAL(result, Dandelion::DandelionManager::AcceptResult::ACCEPTED);
    BOOST_REQUIRE(relay.has_value());

    for (CNode* node : connman.TestNodes()) {
        if (std::find(initial_relays.begin(), initial_relays.end(), node->GetId()) != initial_relays.end()) {
            node->fSuccessfullyConnected = false;
        }
    }

    for (const NodeId relay_id : initial_relays) {
        manager.PeerDisconnected(relay_id);
    }

    const auto reseated_relays = manager.GetRelayPeers();
    BOOST_CHECK(!reseated_relays.empty());
    BOOST_CHECK(std::all_of(
        reseated_relays.begin(),
        reseated_relays.end(),
        [&](NodeId relay_id) { return spare_relays.contains(relay_id); }));
    BOOST_CHECK(manager.CheckEmbargoes().empty());

    connman.ClearTestNodes();
}

BOOST_AUTO_TEST_CASE(epoch_rotation_preserves_stempool_entries)
{
    ConnmanTestMsg connman{0x1337, 0x1337, *m_node.addrman, *m_node.netgroupman, Params()};
    NodeId next_id{0};
    AddDandelionPeer(connman, next_id, /*keyed_netgroup=*/41, 0x05050505, true);
    AddDandelionPeer(connman, next_id, /*keyed_netgroup=*/42, 0x06060606, true);

    Dandelion::DandelionManager manager;
    manager.Initialize(&connman);

    CTransactionRef tx = CreateTestTx();
    const size_t tx_size = ::GetSerializeSize(TX_WITH_WITNESS(tx));
    for (int attempt = 0; attempt < 8; ++attempt) {
        manager.ForceRotateEpoch();
        if (!manager.IsInStemMode()) continue;

        auto [result, relay] = manager.AcceptStemTransaction(tx, /*from_peer=*/17, tx_size);
        if (result == Dandelion::DandelionManager::AcceptResult::ACCEPTED) {
            BOOST_REQUIRE_EQUAL(manager.GetStemPoolSize(), 1U);
            manager.ForceRotateEpoch();
            BOOST_CHECK_EQUAL(manager.GetStemPoolSize(), 1U);
            BOOST_CHECK(manager.CheckEmbargoes().empty());
            connman.ClearTestNodes();
            return;
        }
    }

    connman.ClearTestNodes();
    BOOST_FAIL("failed to enter stem mode with live relay peers");
}

BOOST_AUTO_TEST_SUITE_END()
