// Copyright (c) 2024-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://www.opensource.org/licenses/mit-license.php.

#include <blockencodings.h>
#include <chainparams.h>
#include <consensus/merkle.h>
#include <node/miner.h>
#include <node/transaction.h>
#include <net_processing.h>
#include <test/util/mining.h>
#include <test/util/net.h>
#include <test/util/setup_common.h>
#include <validation.h>

#include <algorithm>
#include <atomic>
#include <limits>
#include <thread>

#include <boost/test/unit_test.hpp>

BOOST_FIXTURE_TEST_SUITE(peerman_tests, RegTestingSetup)

/** Window, in blocks, for connecting to NODE_NETWORK_LIMITED peers */
static constexpr int64_t NODE_NETWORK_LIMITED_ALLOW_CONN_BLOCKS = 144;

static bool HasQueuedMessageType(CNode& node, const std::string& msg_type)
{
    LOCK(node.cs_vSend);
    const auto& [bytes, _more, transport_type] =
        node.m_transport->GetBytesToSend(!node.vSendMsg.empty());
    if (!bytes.empty() && transport_type == msg_type) return true;
    return std::any_of(node.vSendMsg.begin(), node.vSendMsg.end(),
                       [&](const CSerializedNetMsg& msg) {
                           return msg.m_type == msg_type;
                       });
}

static void mineBlock(const node::NodeContext& node, std::chrono::seconds block_time)
{
    auto curr_time = GetTime<std::chrono::seconds>();
    SetMockTime(block_time); // update time so the block is created with it
    CBlock block = node::BlockAssembler{node.chainman->ActiveChainstate(), nullptr, {}, node}.CreateNewBlock()->block;
    const CBlockIndex* prev_index{WITH_LOCK(::cs_main, return node.chainman->ActiveChain().Tip())};
    const uint32_t block_height{prev_index ? static_cast<uint32_t>(prev_index->nHeight + 1) : 0};
    BOOST_REQUIRE(MineHeaderForConsensus(
        block,
        block_height,
        node.chainman->GetConsensus(),
        5'000'000,
        prev_index ? std::optional<int64_t>{prev_index->GetMedianTimePast()} : std::nullopt));
    block.fChecked = true; // little speedup
    SetMockTime(curr_time); // process block at current time
    Assert(node.chainman->ProcessNewBlock(std::make_shared<const CBlock>(block), /*force_processing=*/true, /*min_pow_checked=*/true, nullptr));
    node.validation_signals->SyncWithValidationInterfaceQueue(); // drain events queue
}

// Verifying when network-limited peer connections are desirable based on the node's proximity to the tip
BOOST_AUTO_TEST_CASE(connections_desirable_service_flags)
{
    std::unique_ptr<PeerManager> peerman = PeerManager::make(*m_node.connman, *m_node.addrman, nullptr, *m_node.chainman, *m_node.mempool, *m_node.warnings, {});
    auto consensus = m_node.chainman->GetParams().GetConsensus();
    // Pre-RC tip: do not require NODE_MATMUL_CONSENSUS (production canary may
    // still be unpublished). After RC activation the MatMul-specific case
    // below covers the consensus-tier preference.
    const ServiceFlags desirable_full{
        ServiceFlags(NODE_NETWORK | NODE_WITNESS)};
    const ServiceFlags desirable_limited{
        ServiceFlags(NODE_NETWORK_LIMITED | NODE_WITNESS)};

    // Check we start connecting to full nodes
    ServiceFlags peer_flags{NODE_WITNESS | NODE_NETWORK_LIMITED};
    BOOST_CHECK(peerman->GetDesirableServiceFlags(peer_flags) == desirable_full);

    // Make peerman aware of the initial best block and verify we accept limited peers when we start close to the tip time.
    auto tip = WITH_LOCK(::cs_main, return m_node.chainman->ActiveChain().Tip());
    uint64_t tip_block_time = tip->GetBlockTime();
    int tip_block_height = tip->nHeight;
    peerman->SetBestBlock(tip_block_height, std::chrono::seconds{tip_block_time});

    SetMockTime(tip_block_time + 1); // Set node time to tip time
    BOOST_CHECK(peerman->GetDesirableServiceFlags(peer_flags) == desirable_limited);

    // Check we don't disallow limited peers connections when we are behind but still recoverable (below the connection safety window)
    SetMockTime(GetTime<std::chrono::seconds>() + std::chrono::seconds{consensus.nPowTargetSpacing * (NODE_NETWORK_LIMITED_ALLOW_CONN_BLOCKS - 1)});
    BOOST_CHECK(peerman->GetDesirableServiceFlags(peer_flags) == desirable_limited);

    // Check we disallow limited peers connections when we are further than the limited peers safety window
    SetMockTime(GetTime<std::chrono::seconds>() + std::chrono::seconds{consensus.nPowTargetSpacing * 2});
    BOOST_CHECK(peerman->GetDesirableServiceFlags(peer_flags) == desirable_full);

    // By now, we tested that the connections desirable services flags change based on the node's time proximity to the tip.
    // Now, perform the same tests for when the node receives a block.
    m_node.validation_signals->RegisterValidationInterface(peerman.get());

    // First, verify a block in the past doesn't enable limited peers connections
    // At this point, our time is (NODE_NETWORK_LIMITED_ALLOW_CONN_BLOCKS + 1) * 10 minutes ahead the tip's time.
    mineBlock(m_node, /*block_time=*/std::chrono::seconds{tip_block_time + 1});
    BOOST_CHECK(peerman->GetDesirableServiceFlags(peer_flags) == desirable_full);

    // Verify a block close to the tip enables limited peers connections
    mineBlock(m_node, /*block_time=*/GetTime<std::chrono::seconds>());
    BOOST_CHECK(peerman->GetDesirableServiceFlags(peer_flags) == desirable_limited);

    // Lastly, verify the stale tip checks can disallow limited peers connections after not receiving blocks for a prolonged period.
    SetMockTime(GetTime<std::chrono::seconds>() + std::chrono::seconds{consensus.nPowTargetSpacing * NODE_NETWORK_LIMITED_ALLOW_CONN_BLOCKS + 1});
    BOOST_CHECK(peerman->GetDesirableServiceFlags(peer_flags) == desirable_full);
}

// Regression: HasAllDesirableServiceFlags / GetDesirableServiceFlags must not
// take cs_main. ThreadOpenConnections calls them on the outbound-connect hot
// path; if they block on cs_main while msghand holds it across
// ProcessNewBlock/SyncWithValidationInterfaceQueue, the node stops opening
// connections (macpro2 deadlock secondary damage, 2026-08-11).
BOOST_AUTO_TEST_CASE(desirable_flags_do_not_block_on_cs_main)
{
    std::unique_ptr<PeerManager> peerman = PeerManager::make(
        *m_node.connman, *m_node.addrman, nullptr, *m_node.chainman,
        *m_node.mempool, *m_node.warnings, {});
    auto tip = WITH_LOCK(::cs_main, return m_node.chainman->ActiveChain().Tip());
    peerman->SetBestBlock(tip->nHeight, std::chrono::seconds{tip->GetBlockTime()});

    std::atomic<bool> holder_ready{false};
    std::atomic<bool> release_holder{false};
    std::thread cs_main_holder([&] {
        LOCK(::cs_main);
        holder_ready.store(true, std::memory_order_release);
        while (!release_holder.load(std::memory_order_acquire)) {
            std::this_thread::sleep_for(std::chrono::milliseconds{1});
        }
    });
    while (!holder_ready.load(std::memory_order_acquire)) {
        std::this_thread::yield();
    }

    // Must complete while another thread holds cs_main. A regression that
    // reintroduces LOCK(cs_main) here deadlocks this test.
    const ServiceFlags peer_flags{NODE_WITNESS | NODE_NETWORK};
    const auto desirable = peerman->GetDesirableServiceFlags(peer_flags);
    BOOST_CHECK((desirable & NODE_NETWORK) != 0);
    BOOST_CHECK(peerman->HasAllDesirableServiceFlags(desirable));

    release_holder.store(true, std::memory_order_release);
    cs_main_holder.join();
}

BOOST_AUTO_TEST_CASE(matmul_consensus_tier_desirable_service_flags)
{
    std::unique_ptr<PeerManager> peerman = PeerManager::make(*m_node.connman, *m_node.addrman, nullptr, *m_node.chainman, *m_node.mempool, *m_node.warnings, {});

    const ServiceFlags base{ServiceFlags(NODE_NETWORK | NODE_WITNESS)};
    const ServiceFlags consensus_peer{ServiceFlags(base | NODE_MATMUL_CONSENSUS)};
    const ServiceFlags economic_peer{ServiceFlags(base | NODE_MATMUL_ECONOMIC)};

    // Default regtest tip is below nMatMulRCHeight, so consensus-mode sync must
    // still treat ordinary NODE_NETWORK peers as desirable. Otherwise two
    // self-qualified CUDA nodes with an empty production golden manifest can
    // never sync the pre-activation parent chain.
    auto tip = WITH_LOCK(::cs_main, return m_node.chainman->ActiveChain().Tip());
    peerman->SetBestBlock(tip->nHeight, std::chrono::seconds{tip->GetBlockTime()});
    BOOST_REQUIRE(!m_node.chainman->GetParams().GetConsensus().IsMatMulRCActive(
        tip->nHeight));
    BOOST_CHECK(peerman->GetDesirableServiceFlags(base) == base);
    BOOST_CHECK(peerman->HasAllDesirableServiceFlags(base));
    BOOST_CHECK(peerman->HasAllDesirableServiceFlags(consensus_peer));
    BOOST_CHECK(peerman->HasAllDesirableServiceFlags(economic_peer));

    // Force RC-active height identity for the preference gate without mining a
    // full activation window. Restore immediately so later tests stay hermetic.
    Consensus::Params& consensus = const_cast<Consensus::Params&>(
        m_node.chainman->GetParams().GetConsensus());
    const int32_t saved_rc = consensus.nMatMulRCHeight;
    const int32_t saved_v4 = consensus.nMatMulV4Height;
    struct RestoreHeights {
        Consensus::Params& params;
        int32_t rc;
        int32_t v4;
        ~RestoreHeights()
        {
            params.nMatMulRCHeight = rc;
            params.nMatMulV4Height = v4;
        }
    } restore{consensus, saved_rc, saved_v4};
    consensus.nMatMulV4Height = 0;
    consensus.nMatMulRCHeight = 0;
    BOOST_REQUIRE(consensus.IsMatMulRCActive(tip->nHeight));
    BOOST_CHECK(peerman->GetDesirableServiceFlags(base) ==
                ServiceFlags(base | NODE_MATMUL_CONSENSUS));
    BOOST_CHECK(peerman->HasAllDesirableServiceFlags(consensus_peer));
    BOOST_CHECK(!peerman->HasAllDesirableServiceFlags(base));
    BOOST_CHECK(!peerman->HasAllDesirableServiceFlags(economic_peer));
}

BOOST_AUTO_TEST_CASE(matmul_consensus_tier_sync_eligibility_tracks_activation)
{
    const ServiceFlags base{ServiceFlags(NODE_NETWORK | NODE_WITNESS)};
    const ServiceFlags consensus_peer{
        ServiceFlags(base | NODE_MATMUL_CONSENSUS)};

    // A peer selected before activation remains eligible while the tier is
    // optional, but is dynamically disqualified once the tier is required.
    BOOST_CHECK(IsMatMulPeerEligibleForSync(
        /*require_matmul_consensus=*/false, base,
        /*has_noban_permission=*/false));
    BOOST_CHECK(!IsMatMulPeerEligibleForSync(
        /*require_matmul_consensus=*/true, base,
        /*has_noban_permission=*/false));
    BOOST_CHECK(IsMatMulPeerEligibleForSync(
        /*require_matmul_consensus=*/true, consensus_peer,
        /*has_noban_permission=*/false));
    BOOST_CHECK(IsMatMulPeerEligibleForSync(
        /*require_matmul_consensus=*/true, base,
        /*has_noban_permission=*/true));

    BOOST_CHECK(!ShouldRequestBlocksFromMatMulPeer(
        /*can_serve_blocks=*/true, /*peer_is_eligible=*/false,
        /*request_window_open=*/true,
        /*sync_blocks_and_headers_from_peer=*/true,
        /*limited_peer=*/false, /*initial_block_download=*/false,
        /*blocks_in_flight=*/0, /*max_blocks_in_flight=*/16));
    BOOST_CHECK(ShouldRequestBlocksFromMatMulPeer(
        /*can_serve_blocks=*/true, /*peer_is_eligible=*/true,
        /*request_window_open=*/true,
        /*sync_blocks_and_headers_from_peer=*/true,
        /*limited_peer=*/false, /*initial_block_download=*/false,
        /*blocks_in_flight=*/0, /*max_blocks_in_flight=*/16));
    BOOST_CHECK(!ShouldRequestBlocksFromMatMulPeer(
        /*can_serve_blocks=*/true, /*peer_is_eligible=*/true,
        /*request_window_open=*/false,
        /*sync_blocks_and_headers_from_peer=*/true,
        /*limited_peer=*/false, /*initial_block_download=*/false,
        /*blocks_in_flight=*/0, /*max_blocks_in_flight=*/16));
}

BOOST_AUTO_TEST_CASE(matmul_consensus_tier_preferred_state_reconciles_at_activation)
{
    bool preferred_download{true};
    int preferred_download_count{1};

    // The VERSION-time preference remains while the connected peer is still
    // eligible (including before the RC boundary).
    auto result{ReconcileMatMulPreferredDownloadForSync(
        preferred_download, preferred_download_count,
        /*peer_is_eligible=*/true)};
    BOOST_CHECK(!result.removed);
    BOOST_CHECK(!result.counter_inconsistent);
    BOOST_CHECK(preferred_download);
    BOOST_CHECK_EQUAL(preferred_download_count, 1);

    // Crossing the activation boundary without reconnecting removes the stale
    // preference and its one aggregate-counter contribution exactly once.
    result = ReconcileMatMulPreferredDownloadForSync(
        preferred_download, preferred_download_count,
        /*peer_is_eligible=*/false);
    BOOST_CHECK(result.removed);
    BOOST_CHECK(!result.counter_inconsistent);
    BOOST_CHECK(!preferred_download);
    BOOST_CHECK_EQUAL(preferred_download_count, 0);

    result = ReconcileMatMulPreferredDownloadForSync(
        preferred_download, preferred_download_count,
        /*peer_is_eligible=*/false);
    BOOST_CHECK(!result.removed);
    BOOST_CHECK(!result.counter_inconsistent);
    BOOST_CHECK_EQUAL(preferred_download_count, 0);

    // A pre-existing counter inconsistency saturates instead of becoming a
    // remotely triggerable assertion/underflow at the activation boundary.
    preferred_download = true;
    result = ReconcileMatMulPreferredDownloadForSync(
        preferred_download, preferred_download_count,
        /*peer_is_eligible=*/false);
    BOOST_CHECK(result.removed);
    BOOST_CHECK(result.counter_inconsistent);
    BOOST_CHECK(!preferred_download);
    BOOST_CHECK_EQUAL(preferred_download_count, 0);

    preferred_download = true;
    preferred_download_count = -3;
    result = ReconcileMatMulPreferredDownloadForSync(
        preferred_download, preferred_download_count,
        /*peer_is_eligible=*/false);
    BOOST_CHECK(result.removed);
    BOOST_CHECK(result.counter_inconsistent);
    BOOST_CHECK(!preferred_download);
    BOOST_CHECK_EQUAL(preferred_download_count, 0);
}

BOOST_AUTO_TEST_CASE(matmul_consensus_tier_connected_peer_loses_preference_at_activation)
{
    LOCK(NetEventsInterface::g_msgproc_mutex);

    ConnmanTestMsg& connman = static_cast<ConnmanTestMsg&>(*m_node.connman);
    PeerManager& peerman = *m_node.peerman;
    const ServiceFlags base{ServiceFlags(NODE_NETWORK | NODE_WITNESS)};
    const ServiceFlags consensus_services{
        ServiceFlags(base | NODE_MATMUL_CONSENSUS)};

    const auto saved_mock_time{GetMockTime()};
    struct RestoreMockTime {
        std::chrono::seconds saved;
        ~RestoreMockTime() { SetMockTime(saved); }
    } restore_mock_time{saved_mock_time};
    const CBlockIndex* starting_tip{
        WITH_LOCK(::cs_main, return m_node.chainman->ActiveChain().Tip())};
    BOOST_REQUIRE(starting_tip != nullptr);
    // The genesis header has no predecessor and is therefore treated as an
    // unconnecting HEADERS announcement. Mine one pre-activation block so the
    // real header-processing path can update peer availability and protection.
    mineBlock(m_node, std::chrono::seconds{starting_tip->GetBlockTime() + 1});
    const CBlockIndex* tip{
        WITH_LOCK(::cs_main, return m_node.chainman->ActiveChain().Tip())};
    BOOST_REQUIRE(tip != nullptr);
    SetMockTime(std::chrono::seconds{tip->GetBlockTime()} +
                std::chrono::hours{48});

    CNode ordinary_peer{/*id=*/1,
                        /*sock=*/nullptr,
                        CAddress{},
                        /*nKeyedNetGroupIn=*/0,
                        /*nLocalHostNonceIn=*/0,
                        CAddress{},
                        /*addrNameIn=*/"ordinary-pre-rc",
                        ConnectionType::OUTBOUND_FULL_RELAY,
                        /*inbound_onion=*/false,
                        /*network_key=*/0};
    CNode consensus_peer{/*id=*/2,
                         /*sock=*/nullptr,
                         CAddress{},
                         /*nKeyedNetGroupIn=*/0,
                         /*nLocalHostNonceIn=*/0,
                         CAddress{},
                         /*addrNameIn=*/"consensus-pre-rc",
                         ConnectionType::OUTBOUND_FULL_RELAY,
                         /*inbound_onion=*/false,
                         /*network_key=*/0};

    connman.Handshake(ordinary_peer, /*successfully_connected=*/true, base,
                      base, PROTOCOL_VERSION, /*relay_txs=*/true);
    connman.Handshake(consensus_peer, /*successfully_connected=*/true,
                      consensus_services, base, PROTOCOL_VERSION,
                      /*relay_txs=*/true);
    // Handshake leaves ordinary outbound traffic queued after the final
    // SendMessages call. Drain it before injecting a synthetic inbound HEADERS
    // message through the same transport.
    connman.FlushSendBuffer(ordinary_peer);

    struct FinalizePeers {
        PeerManager& peerman;
        CNode& ordinary;
        CNode& consensus;
        ~FinalizePeers()
        {
            peerman.FinalizeNode(ordinary);
            peerman.FinalizeNode(consensus);
        }
    } finalize{peerman, ordinary_peer, consensus_peer};

    // Exercise the real chain-sync protection path before activation. The
    // ordinary full-outbound peer must relinquish this slot at the boundary.
    std::vector<CBlock> known_headers{
        CBlock{tip->GetBlockHeader()}};
    auto headers_msg{
        NetMsg::Make(NetMsgType::HEADERS, TX_WITH_WITNESS(known_headers))};
    BOOST_REQUIRE(connman.ReceiveMsgFrom(ordinary_peer, std::move(headers_msg)));
    ordinary_peer.fPauseSend = false;
    (void)connman.ProcessMessagesOnce(ordinary_peer);

    CNodeStateStats ordinary_stats;
    CNodeStateStats consensus_stats;
    BOOST_REQUIRE(peerman.GetNodeStateStats(ordinary_peer.GetId(), ordinary_stats));
    BOOST_REQUIRE(peerman.GetNodeStateStats(consensus_peer.GetId(), consensus_stats));
    BOOST_REQUIRE(ordinary_stats.m_preferred_download);
    BOOST_REQUIRE(consensus_stats.m_preferred_download);
    BOOST_REQUIRE_EQUAL(ordinary_stats.m_total_preferred_download_peer_count, 2);
    BOOST_REQUIRE_EQUAL(consensus_stats.m_total_preferred_download_peer_count, 2);
    BOOST_REQUIRE(ordinary_stats.m_headers_sync_started);
    BOOST_REQUIRE(!consensus_stats.m_headers_sync_started);
    BOOST_REQUIRE_EQUAL(ordinary_stats.m_total_headers_sync_peer_count, 1);
    BOOST_REQUIRE_EQUAL(consensus_stats.m_total_headers_sync_peer_count, 1);
    BOOST_REQUIRE(ordinary_stats.m_chain_sync_protected);
    BOOST_REQUIRE_EQUAL(
        ordinary_stats.m_total_chain_sync_protected_peer_count, 1);

    Consensus::Params& consensus = const_cast<Consensus::Params&>(
        m_node.chainman->GetParams().GetConsensus());
    const int32_t saved_rc = consensus.nMatMulRCHeight;
    const int32_t saved_v4 = consensus.nMatMulV4Height;
    struct RestoreHeights {
        Consensus::Params& params;
        int32_t rc;
        int32_t v4;
        ~RestoreHeights()
        {
            params.nMatMulRCHeight = rc;
            params.nMatMulV4Height = v4;
        }
    } restore{consensus, saved_rc, saved_v4};
    consensus.nMatMulV4Height = 0;
    consensus.nMatMulRCHeight = 0;
    BOOST_REQUIRE(consensus.IsMatMulRCActive(
        WITH_LOCK(::cs_main, return m_node.chainman->ActiveChain().Height())));

    // If the eligible peer is visited first, the ineligible peer still owns
    // the single stale header-sync slot for at most this message-processing
    // round. No reconnect is required for the subsequent handoff.
    BOOST_CHECK(peerman.SendMessages(&consensus_peer));
    BOOST_REQUIRE(peerman.GetNodeStateStats(consensus_peer.GetId(), consensus_stats));
    BOOST_REQUIRE(!consensus_stats.m_headers_sync_started);
    BOOST_REQUIRE_EQUAL(consensus_stats.m_total_headers_sync_peer_count, 1);

    // Exercise the production SendMessages selection hook. The ordinary peer
    // loses both VERSION-time preference and header-sync ownership exactly once.
    BOOST_CHECK(peerman.SendMessages(&ordinary_peer));
    BOOST_REQUIRE(peerman.GetNodeStateStats(ordinary_peer.GetId(), ordinary_stats));
    BOOST_REQUIRE(!ordinary_stats.m_preferred_download);
    BOOST_REQUIRE_EQUAL(ordinary_stats.m_total_preferred_download_peer_count, 1);
    BOOST_REQUIRE(!ordinary_stats.m_headers_sync_started);
    BOOST_REQUIRE_EQUAL(ordinary_stats.m_total_headers_sync_peer_count, 0);
    BOOST_REQUIRE(!ordinary_stats.m_chain_sync_protected);
    BOOST_REQUIRE_EQUAL(
        ordinary_stats.m_total_chain_sync_protected_peer_count, 0);
    BOOST_REQUIRE(ordinary_peer.fDisconnect);

    BOOST_CHECK(peerman.SendMessages(&ordinary_peer));
    BOOST_CHECK(peerman.SendMessages(&consensus_peer));
    BOOST_REQUIRE(peerman.GetNodeStateStats(ordinary_peer.GetId(), ordinary_stats));
    BOOST_REQUIRE(peerman.GetNodeStateStats(consensus_peer.GetId(), consensus_stats));
    BOOST_CHECK(!ordinary_stats.m_preferred_download);
    BOOST_CHECK(consensus_stats.m_preferred_download);
    BOOST_CHECK_EQUAL(ordinary_stats.m_total_preferred_download_peer_count, 1);
    BOOST_CHECK_EQUAL(consensus_stats.m_total_preferred_download_peer_count, 1);
    BOOST_CHECK(!ordinary_stats.m_headers_sync_started);
    BOOST_CHECK(consensus_stats.m_headers_sync_started);
    BOOST_CHECK_EQUAL(ordinary_stats.m_total_headers_sync_peer_count, 1);
    BOOST_CHECK_EQUAL(consensus_stats.m_total_headers_sync_peer_count, 1);
    BOOST_CHECK(!consensus_peer.fDisconnect);
}

BOOST_AUTO_TEST_CASE(matmul_consensus_tier_compact_block_boundary_policy)
{
    LOCK(NetEventsInterface::g_msgproc_mutex);

    ConnmanTestMsg& connman = static_cast<ConnmanTestMsg&>(*m_node.connman);
    PeerManager& peerman = *m_node.peerman;
    const ServiceFlags base{ServiceFlags(NODE_NETWORK | NODE_WITNESS)};

    const auto saved_mock_time{GetMockTime()};
    struct RestoreMockTime {
        std::chrono::seconds saved;
        ~RestoreMockTime() { SetMockTime(saved); }
    } restore_mock_time{saved_mock_time};

    CNode pre_boundary_peer{/*id=*/3,
                            /*sock=*/nullptr,
                            CAddress{},
                            /*nKeyedNetGroupIn=*/0,
                            /*nLocalHostNonceIn=*/0,
                            CAddress{},
                            /*addrNameIn=*/"ordinary-compact-pre-rc",
                            ConnectionType::OUTBOUND_FULL_RELAY,
                            /*inbound_onion=*/false,
                            /*network_key=*/0};
    CNode post_boundary_peer{/*id=*/4,
                             /*sock=*/nullptr,
                             CAddress{},
                             /*nKeyedNetGroupIn=*/0,
                             /*nLocalHostNonceIn=*/0,
                             CAddress{},
                             /*addrNameIn=*/"ordinary-compact-post-rc",
                             ConnectionType::OUTBOUND_FULL_RELAY,
                             /*inbound_onion=*/false,
                             /*network_key=*/0};
    connman.Handshake(pre_boundary_peer, /*successfully_connected=*/true, base,
                      base, PROTOCOL_VERSION, /*relay_txs=*/true);
    connman.Handshake(post_boundary_peer, /*successfully_connected=*/true, base,
                      base, PROTOCOL_VERSION, /*relay_txs=*/true);
    connman.FlushSendBuffer(pre_boundary_peer);
    connman.FlushSendBuffer(post_boundary_peer);
    const auto negotiate_compact_relay = [&](CNode& node)
        EXCLUSIVE_LOCKS_REQUIRED(NetEventsInterface::g_msgproc_mutex) {
        auto sendcmpct{NetMsg::Make(
            NetMsgType::SENDCMPCT, /*high_bandwidth=*/true,
            /*witness compact-block version=*/uint64_t{2})};
        BOOST_REQUIRE(connman.ReceiveMsgFrom(node, std::move(sendcmpct)));
        node.fPauseSend = false;
        (void)connman.ProcessMessagesOnce(node);
        // Model the reciprocal SENDCMPCT(1) already sent by our side without
        // leaving unrelated handshake bytes in the queue under inspection.
        node.m_bip152_highbandwidth_to = true;
        connman.FlushSendBuffer(node);
    };
    negotiate_compact_relay(pre_boundary_peer);
    negotiate_compact_relay(post_boundary_peer);

    struct FinalizePeers {
        PeerManager& peerman;
        CNode& first;
        CNode& second;
        ~FinalizePeers()
        {
            peerman.FinalizeNode(first);
            peerman.FinalizeNode(second);
        }
    } finalize{peerman, pre_boundary_peer, post_boundary_peer};

    const CBlockIndex* tip{
        WITH_LOCK(::cs_main, return m_node.chainman->ActiveChain().Tip())};
    BOOST_REQUIRE(tip != nullptr);
    SetMockTime(std::chrono::seconds{tip->GetBlockTime() + 1});

    Consensus::Params& consensus = const_cast<Consensus::Params&>(
        m_node.chainman->GetParams().GetConsensus());
    const int32_t saved_rc = consensus.nMatMulRCHeight;
    const int32_t saved_v4 = consensus.nMatMulV4Height;
    const int32_t saved_bmx4c = consensus.nMatMulBMX4CHeight;
    const int32_t saved_drlt = consensus.nMatMulDRLTHeight;
    struct RestoreHeights {
        Consensus::Params& params;
        int32_t rc;
        int32_t v4;
        int32_t bmx4c;
        int32_t drlt;
        ~RestoreHeights()
        {
            params.nMatMulRCHeight = rc;
            params.nMatMulV4Height = v4;
            params.nMatMulBMX4CHeight = bmx4c;
            params.nMatMulDRLTHeight = drlt;
        }
    } restore_heights{
        consensus, saved_rc, saved_v4, saved_bmx4c, saved_drlt};

    const int boundary_height{tip->nHeight + 1};
    consensus.nMatMulV4Height = boundary_height;
    consensus.nMatMulBMX4CHeight = boundary_height;
    consensus.nMatMulDRLTHeight = std::numeric_limits<int32_t>::max();
    consensus.nMatMulRCHeight = boundary_height;
    BOOST_REQUIRE(!consensus.IsMatMulRCActive(
        WITH_LOCK(::cs_main, return m_node.chainman->ActiveChain().Height())));
    BOOST_REQUIRE_EQUAL(peerman.GetDesirableServiceFlags(base), base);

    // The first RC child is not yet authenticated chainwork, so an ordinary
    // peer remains able to announce its header and deliver its body. Only local
    // ExactReplay can move the active chain across the boundary. In particular,
    // indexing an unauthenticated boundary header must not rotate away the only
    // available body source.
    CBlock boundary_candidate = node::BlockAssembler{
        m_node.chainman->ActiveChainstate(), nullptr, {}, m_node}
                                    .CreateNewBlock()
                                    ->block;
    boundary_candidate.hashMerkleRoot = BlockMerkleRoot(boundary_candidate);
    const uint256 boundary_merkle_root{boundary_candidate.hashMerkleRoot};
    BOOST_REQUIRE(MineHeaderForConsensus(
        boundary_candidate, boundary_height, m_node.chainman->GetConsensus(),
        5'000'000, tip->GetMedianTimePast()));
    BOOST_REQUIRE_EQUAL(boundary_candidate.hashMerkleRoot,
                        boundary_merkle_root);
    BOOST_REQUIRE_EQUAL(BlockMerkleRoot(boundary_candidate),
                        boundary_merkle_root);
    std::vector<CBlock> boundary_headers{
        CBlock{boundary_candidate.GetBlockHeader()}};
    auto pre_boundary_msg{NetMsg::Make(
        NetMsgType::HEADERS, TX_WITH_WITNESS(boundary_headers))};
    BOOST_REQUIRE(connman.ReceiveMsgFrom(pre_boundary_peer,
                                         std::move(pre_boundary_msg)));
    pre_boundary_peer.fPauseSend = false;
    (void)connman.ProcessMessagesOnce(pre_boundary_peer);

    const CBlockIndex* boundary_index{WITH_LOCK(
        ::cs_main,
        return m_node.chainman->m_blockman.LookupBlockIndex(
            boundary_candidate.GetHash()))};
    BOOST_REQUIRE(boundary_index != nullptr);
    BOOST_CHECK(!WITH_LOCK(
        ::cs_main,
        return (boundary_index->nStatus & BLOCK_HAVE_DATA) != 0));
    BOOST_CHECK_EQUAL(
        WITH_LOCK(::cs_main,
                  return boundary_index->nAuthenticatedChainWork.GetHex()),
        tip->nAuthenticatedChainWork.GetHex());
    BOOST_CHECK(WITH_LOCK(
        ::cs_main, return boundary_index->nChainWork >
                               boundary_index->nAuthenticatedChainWork));
    BOOST_CHECK_EQUAL(
        WITH_LOCK(::cs_main,
                  return m_node.chainman->ActiveChain().Tip()->GetBlockHash()),
        tip->GetBlockHash());
    BOOST_CHECK_EQUAL(
        WITH_LOCK(::cs_main,
                  return m_node.chainman->m_best_header->GetBlockHash()),
        tip->GetBlockHash());

    CNodeStateStats pre_boundary_stats;
    BOOST_REQUIRE(peerman.GetNodeStateStats(pre_boundary_peer.GetId(),
                                             pre_boundary_stats));
    BOOST_REQUIRE_EQUAL(pre_boundary_stats.vHeightInFlight.size(), 1U);
    BOOST_CHECK_EQUAL(pre_boundary_stats.vHeightInFlight.front(),
                      boundary_height);
    BOOST_CHECK(HasQueuedMessageType(pre_boundary_peer, NetMsgType::GETDATA));
    BOOST_CHECK(!HasQueuedMessageType(pre_boundary_peer,
                                      NetMsgType::GETBLOCKTXN));
    BOOST_CHECK_EQUAL(peerman.GetDesirableServiceFlags(base), base);
    BOOST_CHECK(pre_boundary_stats.m_preferred_download);
    BOOST_CHECK(peerman.SendMessages(&pre_boundary_peer));
    BOOST_CHECK(!pre_boundary_peer.fDisconnect);
    BOOST_REQUIRE_EQUAL(boundary_candidate.hashMerkleRoot,
                        boundary_merkle_root);
    BOOST_REQUIRE_EQUAL(BlockMerkleRoot(boundary_candidate),
                        boundary_merkle_root);

    bool new_block{false};
    BOOST_REQUIRE(m_node.chainman->ProcessNewBlock(
        std::make_shared<const CBlock>(boundary_candidate),
        /*force_processing=*/true, /*min_pow_checked=*/true, &new_block));
    BOOST_REQUIRE(new_block);
    m_node.validation_signals->SyncWithValidationInterfaceQueue();
    BOOST_REQUIRE(consensus.IsMatMulRCActive(
        WITH_LOCK(::cs_main, return m_node.chainman->ActiveChain().Height())));
    BOOST_REQUIRE_EQUAL(
        WITH_LOCK(::cs_main,
                  return m_node.chainman->ActiveChain().Tip()->GetBlockHash()),
        boundary_candidate.GetHash());
    BOOST_CHECK_EQUAL(
        peerman.GetDesirableServiceFlags(base),
        ServiceFlags(base | NODE_MATMUL_CONSENSUS));
    BOOST_CHECK(peerman.SendMessages(&pre_boundary_peer));
    BOOST_CHECK(pre_boundary_peer.fDisconnect);

    // After the local authenticated tip is RC-active, the same class of peer
    // may still relay a header but must not allocate any compact/full block
    // download state. Mine a valid next RC child so success cannot be explained
    // by malformed-header rejection; the header must enter the block index while
    // its body remains unrequested.
    const CBlockIndex* rc_tip{
        WITH_LOCK(::cs_main, return m_node.chainman->ActiveChain().Tip())};
    BOOST_REQUIRE(rc_tip != nullptr);
    SetMockTime(std::chrono::seconds{rc_tip->GetBlockTime() + 1});
    CBlock post_boundary_candidate = node::BlockAssembler{
        m_node.chainman->ActiveChainstate(), nullptr, {}, m_node}
                                         .CreateNewBlock()
                                         ->block;
    post_boundary_candidate.hashMerkleRoot =
        BlockMerkleRoot(post_boundary_candidate);
    const uint256 post_boundary_merkle_root{
        post_boundary_candidate.hashMerkleRoot};
    BOOST_REQUIRE(MineHeaderForConsensus(
        post_boundary_candidate, rc_tip->nHeight + 1,
        m_node.chainman->GetConsensus(), 5'000'000,
        rc_tip->GetMedianTimePast()));
    BOOST_REQUIRE_EQUAL(post_boundary_candidate.hashMerkleRoot,
                        post_boundary_merkle_root);
    BOOST_REQUIRE_EQUAL(BlockMerkleRoot(post_boundary_candidate),
                        post_boundary_merkle_root);
    CBlockHeaderAndShortTxIDs post_boundary_compact{
        post_boundary_candidate, 2};
    auto post_boundary_msg{NetMsg::Make(
        NetMsgType::CMPCTBLOCK, TX_WITH_WITNESS(post_boundary_compact))};
    BOOST_REQUIRE(connman.ReceiveMsgFrom(post_boundary_peer,
                                         std::move(post_boundary_msg)));
    post_boundary_peer.fPauseSend = false;
    (void)connman.ProcessMessagesOnce(post_boundary_peer);

    CNodeStateStats post_boundary_stats;
    BOOST_REQUIRE(peerman.GetNodeStateStats(post_boundary_peer.GetId(),
                                             post_boundary_stats));
    BOOST_REQUIRE(WITH_LOCK(
        ::cs_main,
        return m_node.chainman->m_blockman.LookupBlockIndex(
                   post_boundary_candidate.GetHash()) != nullptr));
    BOOST_CHECK(post_boundary_stats.vHeightInFlight.empty());
    BOOST_CHECK(!HasQueuedMessageType(post_boundary_peer,
                                      NetMsgType::GETBLOCKTXN));
    BOOST_CHECK(!HasQueuedMessageType(post_boundary_peer,
                                      NetMsgType::GETDATA));
}

BOOST_AUTO_TEST_CASE(broadcast_transaction_fails_closed_without_peerman)
{
    std::unique_ptr<PeerManager> saved_peerman = std::move(m_node.peerman);
    BOOST_REQUIRE(saved_peerman);

    std::string err_string;
    CMutableTransaction mtx;
    const auto tx = MakeTransactionRef(mtx);
    const auto err = node::BroadcastTransaction(m_node, tx, err_string, CAmount{0}, /*relay=*/true, /*wait_callback=*/false);

    BOOST_CHECK(err == node::TransactionError::MEMPOOL_ERROR);
    BOOST_CHECK_EQUAL(err_string, "node shutting down or networking unavailable");

    m_node.peerman = std::move(saved_peerman);
}

BOOST_AUTO_TEST_SUITE_END()
