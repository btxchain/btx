// Copyright (c) 2024-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://www.opensource.org/licenses/mit-license.php.

#include <blockencodings.h>
#include <chainparams.h>
#include <consensus/merkle.h>
#include <key.h>
#include <matmul/trusted_exact_replay_attestation.h>
#include <node/matmul_rc_admission.h>
#include <node/matmul_trusted_attestations.h>
#include <node/block_chunk_transport.h>
#include <node/miner.h>
#include <node/transaction.h>
#include <net_processing.h>
#include <node/kernel_notifications.h>
#include <node/warnings.h>
#include <pow.h>
#include <protocol.h>
#include <script/script.h>
#include <streams.h>
#include <test/util/logging.h>
#include <test/util/mining.h>
#include <test/util/net.h>
#include <test/util/setup_common.h>
#include <validation.h>

#include <algorithm>
#include <atomic>
#include <chrono>
#include <condition_variable>
#include <limits>
#include <mutex>
#include <optional>
#include <stdexcept>
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


// Shared RegTestingSetup: earlier cases (catch-up, have_data) leave
// headers-only forks in m_block_index. MatMulTreatAsIbdForBudget is
// `active_height < best_header`, so those leftovers skip header-first
// ExactReplay in later cases. Mark every unconnected index failed and snap
// m_best_header back to the active tip.
static void NeutralizeUnconnectedHeaders(ChainstateManager& chainman)
{
    LOCK(::cs_main);
    CBlockIndex* tip{const_cast<CBlockIndex*>(chainman.ActiveTip())};
    BOOST_REQUIRE(tip != nullptr);
    for (auto& [hash, index] : chainman.m_blockman.m_block_index) {
        if (chainman.ActiveChain().Contains(&index)) continue;
        chainman.ActiveChainstate().setBlockIndexCandidates.erase(&index);
        if (index.nStatus & BLOCK_FAILED_MASK) continue;
        if (index.pprev != nullptr && chainman.ActiveChain().Contains(index.pprev)) {
            index.nStatus |= BLOCK_FAILED_VALID;
            chainman.m_failed_blocks.insert(&index);
        } else {
            index.nStatus |= BLOCK_FAILED_CHILD;
        }
    }
    // Header-first ExactReplay requires parent nAuthenticatedChainWork ==
    // nChainWork. A prior case may have connected an unattested MatMul tip.
    for (CBlockIndex* walk{tip}; walk != nullptr; walk = walk->pprev) {
        walk->nAuthenticatedChainWork = walk->nChainWork;
    }
    chainman.SetBestHeader(tip);
}

static void ResetSharedPeermanFixture(node::NodeContext& node)
{
    NeutralizeUnconnectedHeaders(*Assert(node.chainman));
    Assert(node.peerman)->ResetMatMulVerifyAdmissionForTest();
    const CBlockIndex* tip{WITH_LOCK(::cs_main, return node.chainman->ActiveTip())};
    BOOST_REQUIRE(tip != nullptr);
    SetMockTime(std::chrono::seconds{tip->GetBlockTime() + 1});
    node.chainman->m_blockman.m_blockfiles_indexed = true;
    node.chainman->m_blockman.m_importing = false;
    {
        LOCK(::cs_main);
        const CBlockIndex* best{node.chainman->m_best_header};
        BOOST_REQUIRE(best != nullptr);
        BOOST_REQUIRE_EQUAL(best->nHeight, tip->nHeight);
        BOOST_REQUIRE(tip->nAuthenticatedChainWork == tip->nChainWork);
    }
    // Header-first ExactReplay is a no-op while IsInitialBlockDownload is
    // true. Prior cases in this shared fixture can leave mock time far ahead
    // of the tip (or the finished-IBD latch unset); snap time and re-latch.
    BOOST_REQUIRE(!node.chainman->IsInitialBlockDownload());
}

static size_t CountQueuedGetDataForHash(CNode& node, const uint256& hash)
{
    LOCK(node.cs_vSend);
    size_t n{0};
    for (const auto& msg : node.vSendMsg) {
        if (msg.m_type != NetMsgType::GETDATA) continue;
        DataStream stream{msg.data};
        std::vector<CInv> inv;
        try {
            stream >> inv;
        } catch (const std::ios_base::failure&) {
            continue;
        }
        for (const auto& item : inv) {
            if (item.hash == hash) ++n;
        }
    }
    return n;
}

static size_t CountQueuedGetMmAttestForHash(CNode& node, const uint256& hash)
{
    LOCK(node.cs_vSend);
    size_t n{0};
    for (const auto& msg : node.vSendMsg) {
        if (msg.m_type != NetMsgType::GETMMATTEST) continue;
        DataStream stream{msg.data};
        uint256 requested;
        try {
            stream >> requested;
        } catch (const std::ios_base::failure&) {
            continue;
        }
        if (requested == hash) ++n;
    }
    return n;
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

BOOST_AUTO_TEST_CASE(block_chunk_manifest_and_assembler_bounds)
{
    using namespace node;
    BlockChunkManifest manifest;
    manifest.block_hash = uint256::ONE;
    manifest.total_size = BLOCK_CHUNK_SIZE + 3;
    manifest.chunk_size = BLOCK_CHUNK_SIZE;
    manifest.chunk_count = 2;
    const std::vector<uint8_t> payload(manifest.total_size, uint8_t{0x5a});
    manifest.payload_hash = Hash(payload);
    BOOST_CHECK(ValidateBlockChunkManifest(manifest));

    BlockChunkManifest malformed{manifest};
    malformed.block_hash = uint256::ZERO;
    BOOST_CHECK(!ValidateBlockChunkManifest(malformed));
    malformed = manifest;
    malformed.total_size = std::numeric_limits<uint64_t>::max();
    BOOST_CHECK(!ValidateBlockChunkManifest(malformed));
    malformed = manifest;
    malformed.total_size = BLOCK_CHUNK_MAX_TOTAL_BYTES + 1;
    BOOST_CHECK(!ValidateBlockChunkManifest(malformed));
    malformed = manifest;
    malformed.chunk_count = 1;
    BOOST_CHECK(!ValidateBlockChunkManifest(malformed));
    malformed = manifest;
    malformed.chunk_size = 0;
    BOOST_CHECK(!ValidateBlockChunkManifest(malformed));
    BlockChunkManifest maximum{manifest};
    maximum.total_size = BLOCK_CHUNK_MAX_TOTAL_BYTES;
    maximum.chunk_count = BLOCK_CHUNK_MAX_COUNT;
    BOOST_CHECK(ValidateBlockChunkManifest(maximum));

    DataStream oversized_wire;
    oversized_wire << manifest.block_hash << uint32_t{0};
    WriteCompactSize(oversized_wire, BLOCK_CHUNK_SIZE + 1);
    BlockChunkMessage oversized_chunk;
    BOOST_CHECK_THROW(oversized_wire >> oversized_chunk,
                      std::ios_base::failure);

    BlockChunkAssembler assembler{manifest};
    BlockChunkMessage second{manifest.block_hash, 1,
                             std::vector<uint8_t>(3, uint8_t{0x5a})};
    BOOST_CHECK(assembler.Add(second) == BlockChunkAddResult::WRONG_INDEX);
    BlockChunkMessage first{manifest.block_hash, 0,
                            std::vector<uint8_t>(BLOCK_CHUNK_SIZE,
                                                 uint8_t{0x5a})};
    BOOST_CHECK(assembler.Add(first) == BlockChunkAddResult::ACCEPTED);
    const uint256 other_hash{
        uint256::FromHex(std::string(64, '2')).value()};
    BlockChunkMessage wrong_block{other_hash, 1,
                                  std::vector<uint8_t>(3, uint8_t{0x5a})};
    BOOST_CHECK(assembler.Add(wrong_block) ==
                BlockChunkAddResult::WRONG_BLOCK);
    BlockChunkMessage wrong_final{manifest.block_hash, 1,
                                  std::vector<uint8_t>(2, uint8_t{0x5a})};
    BOOST_CHECK(assembler.Add(wrong_final) ==
                BlockChunkAddResult::WRONG_SIZE);
    BOOST_CHECK(assembler.Add(second) == BlockChunkAddResult::COMPLETE);
    BOOST_CHECK_EQUAL_COLLECTIONS(assembler.Bytes().begin(),
                                  assembler.Bytes().end(), payload.begin(),
                                  payload.end());

    BlockChunkManifest bad_hash{manifest};
    bad_hash.payload_hash = uint256::ZERO;
    BlockChunkAssembler bad{bad_hash};
    BOOST_CHECK(bad.Add(first) == BlockChunkAddResult::ACCEPTED);
    BOOST_CHECK(bad.Add(second) == BlockChunkAddResult::HASH_MISMATCH);
}

BOOST_AUTO_TEST_CASE(block_chunk_transfer_has_idle_and_absolute_deadlines)
{
    using namespace std::chrono_literals;
    const auto start{std::chrono::steady_clock::time_point{10min}};

    BOOST_CHECK(!node::BlockChunkTransferExpired(
        start, start + 90s, start + 2min));
    BOOST_CHECK(node::BlockChunkTransferExpired(
        start, start + 1min, start + 3min + 1s));

    // Continuous small chunks cannot refresh a reservation indefinitely.
    BOOST_CHECK(node::BlockChunkTransferExpired(
        start, start + 4min + 59s, start + 5min + 1s));
    BOOST_CHECK(node::BlockChunkTransferExpired(
        start, start, start - 1s));
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
// connections.
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

    // Force RC-active height identity without mining a full activation window.
    // MatMul service bits remain scoring hints and never enter the transport
    // service set used by outbound connection acceptance.
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
    BOOST_CHECK(peerman->GetDesirableServiceFlags(base) == base);
    BOOST_CHECK(peerman->HasAllDesirableServiceFlags(consensus_peer));
    BOOST_CHECK(peerman->HasAllDesirableServiceFlags(base));
    BOOST_CHECK(peerman->HasAllDesirableServiceFlags(economic_peer));
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
    // ordinary full-outbound peer must lose preference/protection at the
    // boundary, without being disconnected.
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

    // Preference-only: the ordinary peer loses VERSION-time preference and
    // chain-sync protection, but can retain the liveness-critical header-sync
    // slot and is
    // NOT disconnected. Dropping ineligible outbounds was the CPU-mirror
    // deadlock (peers gone -> no header sync -> nothing fetchable).
    BOOST_CHECK(peerman.SendMessages(&ordinary_peer));
    BOOST_REQUIRE(peerman.GetNodeStateStats(ordinary_peer.GetId(), ordinary_stats));
    BOOST_REQUIRE(!ordinary_stats.m_preferred_download);
    BOOST_REQUIRE_EQUAL(ordinary_stats.m_total_preferred_download_peer_count, 1);
    BOOST_REQUIRE(ordinary_stats.m_headers_sync_started);
    BOOST_REQUIRE_EQUAL(ordinary_stats.m_total_headers_sync_peer_count, 1);
    BOOST_REQUIRE(!ordinary_stats.m_chain_sync_protected);
    BOOST_REQUIRE_EQUAL(
        ordinary_stats.m_total_chain_sync_protected_peer_count, 0);
    BOOST_REQUIRE(!ordinary_peer.fDisconnect);

    BOOST_CHECK(peerman.SendMessages(&ordinary_peer));
    BOOST_CHECK(peerman.SendMessages(&consensus_peer));
    BOOST_REQUIRE(peerman.GetNodeStateStats(ordinary_peer.GetId(), ordinary_stats));
    BOOST_REQUIRE(peerman.GetNodeStateStats(consensus_peer.GetId(), consensus_stats));
    BOOST_CHECK(!ordinary_stats.m_preferred_download);
    BOOST_CHECK(consensus_stats.m_preferred_download);
    BOOST_CHECK_EQUAL(ordinary_stats.m_total_preferred_download_peer_count, 1);
    BOOST_CHECK_EQUAL(consensus_stats.m_total_preferred_download_peer_count, 1);
    BOOST_CHECK(ordinary_stats.m_headers_sync_started);
    BOOST_CHECK(!consensus_stats.m_headers_sync_started);
    BOOST_CHECK_EQUAL(ordinary_stats.m_total_headers_sync_peer_count, 1);
    BOOST_CHECK_EQUAL(consensus_stats.m_total_headers_sync_peer_count, 1);
    BOOST_CHECK(!ordinary_peer.fDisconnect);
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
    // available body source. With the bounded unauth allowance, m_best_header
    // advances onto that header so the body is chased; the active tip stays put
    // until the body authenticates.
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
    // Bounded allowance: chase the unverified RC header; tip stays authenticated.
    BOOST_CHECK_EQUAL(
        WITH_LOCK(::cs_main,
                  return m_node.chainman->m_best_header->GetBlockHash()),
        boundary_candidate.GetHash());
    BOOST_CHECK(WITH_LOCK(
        ::cs_main,
        return PreferTrustAdjustedHeader(*tip, *boundary_index)));

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
        base);
    // Preference-only at the boundary: the pre-boundary ordinary peer loses
    // preferred-download status but stays connected. Disconnecting every
    // ineligible outbound was the CPU-mirror deadlock.
    BOOST_CHECK(peerman.SendMessages(&pre_boundary_peer));
    BOOST_REQUIRE(peerman.GetNodeStateStats(pre_boundary_peer.GetId(),
                                             pre_boundary_stats));
    BOOST_CHECK(!pre_boundary_stats.m_preferred_download);
    BOOST_CHECK(!pre_boundary_peer.fDisconnect);

    // After the local authenticated tip is RC-active, an ordinary peer may
    // still announce and be asked for the next body: fetching is not
    // validating. Mine a valid next RC child so success cannot be explained by
    // malformed-header rejection. The header must enter the block index AND
    // download work must still be allocatable (CMPCT reconstruction and/or
    // GETDATA) -- eligibility must not gate getdata.
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
    // Preference-only: ordinary peer remains usable for download after the
    // boundary. Accept either compact reconstruction (GETBLOCKTXN) or a full
    // GETDATA / in-flight allocation -- any of these proves the gate is gone.
    const bool download_allocated{
        !post_boundary_stats.vHeightInFlight.empty() ||
        HasQueuedMessageType(post_boundary_peer, NetMsgType::GETBLOCKTXN) ||
        HasQueuedMessageType(post_boundary_peer, NetMsgType::GETDATA)};
    BOOST_CHECK(download_allocated);
    BOOST_CHECK(peerman.SendMessages(&post_boundary_peer));
    BOOST_REQUIRE(peerman.GetNodeStateStats(post_boundary_peer.GetId(),
                                             post_boundary_stats));
    BOOST_CHECK(!post_boundary_stats.m_preferred_download);
    BOOST_CHECK(!post_boundary_peer.fDisconnect);
}

// Regression: a trusted mirror whose attestation authority is ahead must
// advance m_best_header along the tip chain when the authority serves
// headers, and must not let competing-branch headers from ordinary peers
// displace that frontier (fra1: headers==blocks frozen while competing
// headers at 186270+ arrived continuously).
BOOST_AUTO_TEST_CASE(trusted_mirror_authority_headers_advance_best_header)
{
    LOCK(NetEventsInterface::g_msgproc_mutex);

    node::matmul_trusted::ResetForTest();
    CKey signer;
    signer.MakeNewKey(/*fCompressed=*/true);
    matmul::trusted::StoreConfig config;
    config.chain_id = uint256::FromHex(std::string(64, '1')).value();
    config.replay_authority_context =
        uint256::FromHex(std::string(64, '2')).value();
    config.trusted_signers = {signer.GetPubKey()};
    config.threshold = 1;
    std::string error;
    BOOST_REQUIRE(node::matmul_trusted::Configure(
        std::move(config), /*trusted_mirror=*/true, /*serve=*/false,
        std::chrono::milliseconds{50}, error));
    BOOST_REQUIRE(node::matmul_trusted::IsTrustedMirror());
    struct MirrorReset {
        ~MirrorReset() { node::matmul_trusted::ResetForTest(); }
    } mirror_reset;

    ConnmanTestMsg& connman = static_cast<ConnmanTestMsg&>(*m_node.connman);
    PeerManager& peerman = *m_node.peerman;

    const ServiceFlags authority_services{ServiceFlags(
        NODE_NETWORK | NODE_WITNESS | NODE_MATMUL_CONSENSUS |
        NODE_MATMUL_ATTESTATION_ARCHIVE)};
    const ServiceFlags ordinary_services{ServiceFlags(
        NODE_NETWORK | NODE_WITNESS | NODE_MATMUL_CONSENSUS)};

    CNode authority{/*id=*/51,
                    /*sock=*/nullptr,
                    CAddress{},
                    /*nKeyedNetGroupIn=*/0,
                    /*nLocalHostNonceIn=*/0,
                    CAddress{},
                    /*addrNameIn=*/"authority-archive",
                    ConnectionType::OUTBOUND_FULL_RELAY,
                    /*inbound_onion=*/false,
                    /*network_key=*/0};
    CNode ordinary{/*id=*/52,
                   /*sock=*/nullptr,
                   CAddress{},
                   /*nKeyedNetGroupIn=*/0,
                   /*nLocalHostNonceIn=*/0,
                   CAddress{},
                   /*addrNameIn=*/"ordinary-competing",
                   ConnectionType::OUTBOUND_FULL_RELAY,
                   /*inbound_onion=*/false,
                   /*network_key=*/0};
    connman.Handshake(authority, /*successfully_connected=*/true,
                      authority_services, authority_services, PROTOCOL_VERSION,
                      /*relay_txs=*/true);
    connman.Handshake(ordinary, /*successfully_connected=*/true,
                      ordinary_services, ordinary_services, PROTOCOL_VERSION,
                      /*relay_txs=*/true);
    connman.FlushSendBuffer(authority);
    connman.FlushSendBuffer(ordinary);
    struct FinalizePeers {
        PeerManager& peerman;
        CNode& first;
        CNode& second;
        ~FinalizePeers()
        {
            peerman.FinalizeNode(first);
            peerman.FinalizeNode(second);
        }
    } finalize{peerman, authority, ordinary};

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
    const int32_t saved_coupled = consensus.nMatMulRCCoupledHeight;
    struct RestoreHeights {
        Consensus::Params& params;
        int32_t rc;
        int32_t v4;
        int32_t bmx4c;
        int32_t drlt;
        int32_t coupled;
        ~RestoreHeights()
        {
            params.nMatMulRCHeight = rc;
            params.nMatMulV4Height = v4;
            params.nMatMulBMX4CHeight = bmx4c;
            params.nMatMulDRLTHeight = drlt;
            params.nMatMulRCCoupledHeight = coupled;
        }
    } restore_heights{consensus, saved_rc, saved_v4, saved_bmx4c, saved_drlt,
                      saved_coupled};

    // RC/trusted-attestation live at the current tip so consensus-tier
    // preference (and the trusted-mirror authority refinement) is active.
    consensus.nMatMulV4Height = tip->nHeight;
    consensus.nMatMulBMX4CHeight = tip->nHeight;
    consensus.nMatMulDRLTHeight = std::numeric_limits<int32_t>::max();
    consensus.nMatMulRCHeight = tip->nHeight;
    consensus.nMatMulRCCoupledHeight = std::numeric_limits<int32_t>::max();
    peerman.SetBestBlock(tip->nHeight, std::chrono::seconds{tip->GetBlockTime()});
    BOOST_REQUIRE(consensus.IsMatMulRCActive(tip->nHeight));
    BOOST_REQUIRE(
        consensus.IsMatMulTrustedReplayAttestationActive(tip->nHeight + 1));

    const int next_height{tip->nHeight + 1};

    // Tip-chain header from the attestation authority.
    CBlock our_next = node::BlockAssembler{
        m_node.chainman->ActiveChainstate(), nullptr, {}, m_node}
                          .CreateNewBlock()
                          ->block;
    our_next.hashMerkleRoot = BlockMerkleRoot(our_next);
    BOOST_REQUIRE(MineHeaderForConsensus(
        our_next, next_height, m_node.chainman->GetConsensus(), 5'000'000,
        tip->GetMedianTimePast()));
    std::vector<CBlock> our_headers{CBlock{our_next.GetBlockHeader()}};
    auto authority_msg{
        NetMsg::Make(NetMsgType::HEADERS, TX_WITH_WITNESS(our_headers))};
    BOOST_REQUIRE(connman.ReceiveMsgFrom(authority, std::move(authority_msg)));
    authority.fPauseSend = false;
    (void)connman.ProcessMessagesOnce(authority);

    const CBlockIndex* our_index{WITH_LOCK(
        ::cs_main,
        return m_node.chainman->m_blockman.LookupBlockIndex(
            our_next.GetHash()))};
    BOOST_REQUIRE(our_index != nullptr);
    BOOST_CHECK_EQUAL(
        WITH_LOCK(::cs_main,
                  return m_node.chainman->m_best_header->GetBlockHash()),
        our_next.GetHash());
    BOOST_CHECK_EQUAL(
        WITH_LOCK(::cs_main, return m_node.chainman->m_best_header->nHeight),
        next_height);

    // Competing fork from tip->pprev (does not extend active tip).
    if (tip->pprev != nullptr) {
        CBlock competing_full;
        competing_full.SetNull();
        competing_full.hashPrevBlock = tip->pprev->GetBlockHash();
        competing_full.nTime = tip->pprev->GetBlockTime() + 2;
        competing_full.nBits = tip->nBits;
        competing_full.nVersion = tip->nVersion;
        competing_full.nNonce = 0;
        competing_full.hashMerkleRoot =
            uint256::FromHex(std::string(64, 'a')).value();
        if (MineHeaderForConsensus(
                competing_full, tip->pprev->nHeight + 1,
                m_node.chainman->GetConsensus(), 5'000'000,
                tip->pprev->GetMedianTimePast())) {
            std::vector<CBlock> competing_headers{
                CBlock{competing_full.GetBlockHeader()}};
            auto ordinary_msg{NetMsg::Make(
                NetMsgType::HEADERS, TX_WITH_WITNESS(competing_headers))};
            BOOST_REQUIRE(
                connman.ReceiveMsgFrom(ordinary, std::move(ordinary_msg)));
            ordinary.fPauseSend = false;
            (void)connman.ProcessMessagesOnce(ordinary);
        }
    }

    BOOST_CHECK_EQUAL(
        WITH_LOCK(::cs_main,
                  return m_node.chainman->m_best_header->GetBlockHash()),
        our_next.GetHash());

    // Raise the authority frontier so the mirror knows it is behind.
    node::matmul_trusted::NoteAuthorityPeerTipHint(next_height + 10);

    CNodeStateStats authority_stats;
    CNodeStateStats ordinary_stats;
    BOOST_CHECK(peerman.SendMessages(&authority));
    BOOST_CHECK(peerman.SendMessages(&ordinary));
    BOOST_REQUIRE(peerman.GetNodeStateStats(authority.GetId(), authority_stats));
    BOOST_REQUIRE(peerman.GetNodeStateStats(ordinary.GetId(), ordinary_stats));
    // The archive bit is discovery only. Until this peer proves authority by
    // delivering a valid MMATTEST it must not receive authority preference.
    BOOST_CHECK(!authority_stats.m_preferred_download);
    BOOST_CHECK(!ordinary_stats.m_preferred_download);

    // Best-header ahead of tip: authority must allocate download toward the
    // tip-chain child (GETDATA / in-flight). That is the path that advances tip
    // once the body + M-of-N quorum arrive.
    const bool download_allocated{
        !authority_stats.vHeightInFlight.empty() ||
        HasQueuedMessageType(authority, NetMsgType::GETDATA)};
    BOOST_CHECK(download_allocated);
}

// Regression: trusted mirror on a divergent (losing) tip must acquire the
// authority's competing-branch headers and allocate download toward them
// without operator invalidateblock. Before the fix, tip-chain-only policy
// treated the authority chain as a competing fork, froze m_best_header at the
// losing tip (headers==blocks), and FindNextBlocks skipped the authority peer
// (outstanding_slots=0).
BOOST_AUTO_TEST_CASE(trusted_mirror_divergent_tip_follows_authority_headers)
{
    LOCK(NetEventsInterface::g_msgproc_mutex);

    ConnmanTestMsg& connman = static_cast<ConnmanTestMsg&>(*m_node.connman);
    PeerManager& peerman = *m_node.peerman;

    const CBlockIndex* fork_parent{
        WITH_LOCK(::cs_main, return m_node.chainman->ActiveChain().Tip())};
    BOOST_REQUIRE(fork_parent != nullptr);
    SetMockTime(std::chrono::seconds{fork_parent->GetBlockTime() + 1});

    Consensus::Params& consensus = const_cast<Consensus::Params&>(
        m_node.chainman->GetParams().GetConsensus());
    const int32_t saved_rc = consensus.nMatMulRCHeight;
    const int32_t saved_v4 = consensus.nMatMulV4Height;
    const int32_t saved_bmx4c = consensus.nMatMulBMX4CHeight;
    const int32_t saved_drlt = consensus.nMatMulDRLTHeight;
    const int32_t saved_coupled = consensus.nMatMulRCCoupledHeight;
    struct RestoreHeights {
        Consensus::Params& params;
        int32_t rc;
        int32_t v4;
        int32_t bmx4c;
        int32_t drlt;
        int32_t coupled;
        ~RestoreHeights()
        {
            params.nMatMulRCHeight = rc;
            params.nMatMulV4Height = v4;
            params.nMatMulBMX4CHeight = bmx4c;
            params.nMatMulDRLTHeight = drlt;
            params.nMatMulRCCoupledHeight = coupled;
        }
    } restore_heights{consensus, saved_rc, saved_v4, saved_bmx4c, saved_drlt,
                      saved_coupled};

    // Keep MatMul activation below the race so connecting the losing tip does
    // not require trusted-attestation admission (we enable the mirror after).
    consensus.nMatMulV4Height = std::numeric_limits<int32_t>::max();
    consensus.nMatMulBMX4CHeight = std::numeric_limits<int32_t>::max();
    consensus.nMatMulDRLTHeight = std::numeric_limits<int32_t>::max();
    consensus.nMatMulRCHeight = std::numeric_limits<int32_t>::max();
    consensus.nMatMulRCCoupledHeight = std::numeric_limits<int32_t>::max();

    const int race_height{fork_parent->nHeight + 1};

    // Losing sibling: connect it as the active tip BEFORE enabling the mirror
    // (production stall starts with an already-connected divergent tip).
    CBlock losing = node::BlockAssembler{
        m_node.chainman->ActiveChainstate(), nullptr, {}, m_node}
                        .CreateNewBlock()
                        ->block;
    losing.hashMerkleRoot = BlockMerkleRoot(losing);
    BOOST_REQUIRE(MineHeaderForConsensus(
        losing, race_height, m_node.chainman->GetConsensus(), 5'000'000,
        fork_parent->GetMedianTimePast()));
    {
        BlockValidationState state;
        const CBlockHeader losing_header{losing.GetBlockHeader()};
        BOOST_REQUIRE(m_node.chainman->ProcessNewBlockHeaders(
            {{losing_header}}, /*min_pow_checked=*/true, state));
        std::shared_ptr<const CBlock> losing_ptr{
            std::make_shared<const CBlock>(losing)};
        BOOST_REQUIRE(m_node.chainman->ProcessNewBlock(
            losing_ptr, /*force_processing=*/true, /*min_pow_checked=*/true,
            nullptr));
    }
    CBlockIndex* losing_tip{WITH_LOCK(
        ::cs_main, return m_node.chainman->ActiveChain().Tip())};
    BOOST_REQUIRE(losing_tip != nullptr);
    BOOST_REQUIRE_EQUAL(losing_tip->nHeight, race_height);
    BOOST_REQUIRE_EQUAL(losing_tip->GetBlockHash(), losing.GetHash());

    // Now become a trusted mirror (stranded on the divergent tip).
    node::matmul_trusted::ResetForTest();
    CKey signer;
    signer.MakeNewKey(/*fCompressed=*/true);
    matmul::trusted::StoreConfig config;
    config.chain_id = uint256::FromHex(std::string(64, '1')).value();
    config.replay_authority_context =
        uint256::FromHex(std::string(64, '2')).value();
    config.trusted_signers = {signer.GetPubKey()};
    config.threshold = 1;
    std::string error;
    BOOST_REQUIRE(node::matmul_trusted::Configure(
        std::move(config), /*trusted_mirror=*/true, /*serve=*/false,
        std::chrono::milliseconds{50}, error));
    BOOST_REQUIRE(node::matmul_trusted::IsTrustedMirror());
    struct MirrorReset {
        ~MirrorReset() { node::matmul_trusted::ResetForTest(); }
    } mirror_reset;

    // Activate RC/attestation at the losing tip so authority preference applies.
    consensus.nMatMulV4Height = losing_tip->nHeight;
    consensus.nMatMulBMX4CHeight = losing_tip->nHeight;
    consensus.nMatMulRCHeight = losing_tip->nHeight;
    peerman.SetBestBlock(losing_tip->nHeight,
                         std::chrono::seconds{losing_tip->GetBlockTime()});
    WITH_LOCK(::cs_main, m_node.chainman->SetBestHeader(losing_tip));
    BOOST_REQUIRE_EQUAL(
        WITH_LOCK(::cs_main,
                  return m_node.chainman->m_best_header->GetBlockHash()),
        losing.GetHash());

    const ServiceFlags authority_services{ServiceFlags(
        NODE_NETWORK | NODE_WITNESS | NODE_MATMUL_CONSENSUS |
        NODE_MATMUL_ATTESTATION_ARCHIVE)};
    const ServiceFlags ordinary_services{ServiceFlags(
        NODE_NETWORK | NODE_WITNESS | NODE_MATMUL_CONSENSUS)};

    CNode authority{/*id=*/61,
                    /*sock=*/nullptr,
                    CAddress{},
                    /*nKeyedNetGroupIn=*/0,
                    /*nLocalHostNonceIn=*/0,
                    CAddress{},
                    /*addrNameIn=*/"authority-divergent",
                    ConnectionType::MANUAL,
                    /*inbound_onion=*/false,
                    /*network_key=*/0};
    CNode ordinary{/*id=*/62,
                   /*sock=*/nullptr,
                   CAddress{},
                   /*nKeyedNetGroupIn=*/0,
                   /*nLocalHostNonceIn=*/0,
                   CAddress{},
                   /*addrNameIn=*/"ordinary-divergent",
                   ConnectionType::OUTBOUND_FULL_RELAY,
                   /*inbound_onion=*/false,
                   /*network_key=*/0};
    connman.Handshake(authority, /*successfully_connected=*/true,
                      authority_services, authority_services, PROTOCOL_VERSION,
                      /*relay_txs=*/true);
    connman.Handshake(ordinary, /*successfully_connected=*/true,
                      ordinary_services, ordinary_services, PROTOCOL_VERSION,
                      /*relay_txs=*/true);
    connman.FlushSendBuffer(authority);
    connman.FlushSendBuffer(ordinary);
    struct FinalizePeers {
        PeerManager& peerman;
        CNode& first;
        CNode& second;
        ~FinalizePeers()
        {
            peerman.FinalizeNode(first);
            peerman.FinalizeNode(second);
        }
    } finalize{peerman, authority, ordinary};

    // Winning sibling at the same height, then one extension (strictly more
    // work) — what the authority actually has after the race resolves.
    CBlock winning;
    winning.SetNull();
    winning.hashPrevBlock = fork_parent->GetBlockHash();
    winning.nTime = fork_parent->GetBlockTime() + 2;
    winning.nBits = losing.nBits;
    winning.nVersion = losing.nVersion;
    winning.nNonce = 0;
    winning.hashMerkleRoot =
        uint256::FromHex(std::string(64, 'c')).value();
    BOOST_REQUIRE(MineHeaderForConsensus(
        winning, race_height, m_node.chainman->GetConsensus(), 5'000'000,
        fork_parent->GetMedianTimePast()));

    CBlock winning_next;
    winning_next.SetNull();
    winning_next.hashPrevBlock = winning.GetHash();
    winning_next.nTime = winning.nTime + 1;
    winning_next.nBits = winning.nBits;
    winning_next.nVersion = winning.nVersion;
    winning_next.nNonce = 0;
    winning_next.hashMerkleRoot =
        uint256::FromHex(std::string(64, 'd')).value();
    BOOST_REQUIRE(MineHeaderForConsensus(
        winning_next, race_height + 1, m_node.chainman->GetConsensus(),
        5'000'000, winning.GetBlockTime()));

    std::vector<CBlock> authority_headers{
        CBlock{winning.GetBlockHeader()},
        CBlock{winning_next.GetBlockHeader()}};
    auto authority_msg{NetMsg::Make(NetMsgType::HEADERS,
                                    TX_WITH_WITNESS(authority_headers))};
    BOOST_REQUIRE(connman.ReceiveMsgFrom(authority, std::move(authority_msg)));
    authority.fPauseSend = false;
    (void)connman.ProcessMessagesOnce(authority);

    const CBlockIndex* winning_next_index{WITH_LOCK(
        ::cs_main,
        return m_node.chainman->m_blockman.LookupBlockIndex(
            winning_next.GetHash()))};
    BOOST_REQUIRE(winning_next_index != nullptr);

    // Headers frontier must leave the losing tip for the authority branch.
    BOOST_CHECK_EQUAL(
        WITH_LOCK(::cs_main,
                  return m_node.chainman->m_best_header->GetBlockHash()),
        winning_next.GetHash());
    BOOST_CHECK_EQUAL(
        WITH_LOCK(::cs_main, return m_node.chainman->m_best_header->nHeight),
        race_height + 1);

    // Ordinary peer offering a different competing fork must not displace it.
    CBlock ordinary_fork;
    ordinary_fork.SetNull();
    ordinary_fork.hashPrevBlock = fork_parent->GetBlockHash();
    ordinary_fork.nTime = fork_parent->GetBlockTime() + 3;
    ordinary_fork.nBits = fork_parent->nBits;
    ordinary_fork.nVersion = fork_parent->nVersion;
    ordinary_fork.nNonce = 0;
    ordinary_fork.hashMerkleRoot =
        uint256::FromHex(std::string(64, 'e')).value();
    if (MineHeaderForConsensus(
            ordinary_fork, race_height, m_node.chainman->GetConsensus(),
            5'000'000, fork_parent->GetMedianTimePast())) {
        std::vector<CBlock> ordinary_headers{
            CBlock{ordinary_fork.GetBlockHeader()}};
        auto ordinary_msg{NetMsg::Make(NetMsgType::HEADERS,
                                       TX_WITH_WITNESS(ordinary_headers))};
        BOOST_REQUIRE(
            connman.ReceiveMsgFrom(ordinary, std::move(ordinary_msg)));
        ordinary.fPauseSend = false;
        (void)connman.ProcessMessagesOnce(ordinary);
    }
    BOOST_CHECK_EQUAL(
        WITH_LOCK(::cs_main,
                  return m_node.chainman->m_best_header->GetBlockHash()),
        winning_next.GetHash());

    node::matmul_trusted::NoteAuthorityPeerTipHint(race_height + 10);

    // After best-header follows the authority branch, an ordinary peer that
    // announces the same chain must be eligible for body download. Authority
    // HeadersDirectFetch already marked the recovery bodies in-flight, so
    // advance mock time past BLOCK_REREQUEST_STALE_AFTER so the ordinary peer
    // may take a duplicate request — the production defect refused that peer
    // entirely with trusted_mirror_not_tip_chain.
    std::vector<CBlock> followed_headers{
        CBlock{winning.GetBlockHeader()},
        CBlock{winning_next.GetBlockHeader()}};
    auto ordinary_followed_msg{NetMsg::Make(
        NetMsgType::HEADERS, TX_WITH_WITNESS(followed_headers))};
    BOOST_REQUIRE(
        connman.ReceiveMsgFrom(ordinary, std::move(ordinary_followed_msg)));
    ordinary.fPauseSend = false;
    (void)connman.ProcessMessagesOnce(ordinary);
    SetMockTime(std::chrono::seconds{GetTime() + 181});
    BOOST_CHECK(peerman.SendMessages(&ordinary));
    CNodeStateStats ordinary_stats;
    BOOST_REQUIRE(peerman.GetNodeStateStats(ordinary.GetId(), ordinary_stats));
    BOOST_CHECK_EQUAL(ordinary_stats.nSyncHeight, race_height + 1);
    const bool ordinary_download{
        !ordinary_stats.vHeightInFlight.empty() ||
        HasQueuedMessageType(ordinary, NetMsgType::GETDATA)};
    BOOST_CHECK(ordinary_download);

    BOOST_CHECK(peerman.SendMessages(&authority));

    CNodeStateStats authority_stats;
    BOOST_REQUIRE(peerman.GetNodeStateStats(authority.GetId(), authority_stats));
    // Authority best-known must be the competing (winning) branch.
    BOOST_CHECK_EQUAL(authority_stats.nSyncHeight, race_height + 1);
    const bool download_allocated{
        !authority_stats.vHeightInFlight.empty() ||
        HasQueuedMessageType(authority, NetMsgType::GETDATA)};
    BOOST_CHECK(download_allocated);
}

// A persisted PARK is branch-specific. It must suppress requests from a peer
// advertising that divergent branch without freezing another peer that can
// supply a body extending the current active tip.
BOOST_AUTO_TEST_CASE(parked_reorg_suppresses_only_parked_peer_downloads)
{
    LOCK(NetEventsInterface::g_msgproc_mutex);

    ChainstateManager& chainman{*Assert(m_node.chainman)};
    PeerManager& peerman{*Assert(m_node.peerman)};
    ConnmanTestMsg& connman{static_cast<ConnmanTestMsg&>(*m_node.connman)};
    const CBlockIndex* starting_tip{
        WITH_LOCK(::cs_main, return chainman.ActiveChain().Tip())};
    BOOST_REQUIRE(starting_tip != nullptr);
    if (starting_tip->pprev == nullptr) {
        mineBlock(m_node,
                  std::chrono::seconds{starting_tip->GetBlockTime() + 1});
    }
    const CBlockIndex* active_tip{
        WITH_LOCK(::cs_main, return chainman.ActiveChain().Tip())};
    BOOST_REQUIRE(active_tip != nullptr);
    BOOST_REQUIRE(active_tip->pprev != nullptr);
    SetMockTime(std::chrono::seconds{active_tip->GetBlockTime() + 10});

    auto make_header = [&](const CBlockIndex& prev, unsigned char tag) {
        CBlock block;
        block.SetNull();
        block.hashPrevBlock = prev.GetBlockHash();
        block.hashMerkleRoot = uint256::FromHex(
            std::string(62, '0') + strprintf("%02x", tag)).value();
        block.nTime = std::max<int64_t>(prev.GetBlockTime() + 1,
                                        GetTime());
        block.nBits = prev.nBits;
        block.nVersion = VERSIONBITS_TOP_BITS;
        BOOST_REQUIRE(MineHeaderForConsensus(
            block, prev.nHeight + 1, chainman.GetConsensus(), 5'000'000,
            prev.GetMedianTimePast()));
        BlockValidationState state;
        const CBlockHeader header{block.GetBlockHeader()};
        BOOST_REQUIRE_MESSAGE(chainman.ProcessNewBlockHeaders(
            {{header}}, /*min_pow_checked=*/true, state), state.ToString());
        CBlockIndex* index{WITH_LOCK(
            ::cs_main,
            return chainman.m_blockman.LookupBlockIndex(block.GetHash()))};
        BOOST_REQUIRE(index != nullptr);
        return index;
    };

    CBlockIndex* active_child{make_header(*active_tip, 0xa1)};
    CBlockIndex* parked_root{make_header(*active_tip->pprev, 0xb1)};
    CBlockIndex* parked_mid{make_header(*parked_root, 0xb2)};
    CBlockIndex* parked_tip{make_header(*parked_mid, 0xb3)};
    BOOST_REQUIRE_EQUAL(parked_tip->nHeight, active_child->nHeight + 1);

    auto& action{const_cast<kernel::DeepReorgAction&>(
        chainman.m_options.deep_reorg_action)};
    const kernel::DeepReorgAction saved_action{action};
    action = kernel::DeepReorgAction::PARK;
    {
        LOCK(::cs_main);
        BOOST_REQUIRE(chainman.ParkReorgBranch(parked_root));
        BOOST_REQUIRE(chainman.IsOnParkedReorgBranch(parked_tip));
        BOOST_REQUIRE_EQUAL(chainman.GetChainRecoveryState().phase,
                            ChainRecoveryPhase::PARKED_NEEDS_OPERATOR);
    }
    struct RestorePark {
        ChainstateManager& chainman;
        kernel::DeepReorgAction& action;
        kernel::DeepReorgAction saved_action;
        CBlockIndex* parked_tip;
        ~RestorePark()
        {
            LOCK(::cs_main);
            chainman.UnparkReorgBranchContainingBlock(parked_tip);
            action = saved_action;
        }
    } restore{chainman, action, saved_action, parked_tip};

    const ServiceFlags services{ServiceFlags(NODE_NETWORK | NODE_WITNESS)};
    CNode active_peer{/*id=*/71, /*sock=*/nullptr, CAddress{},
                      /*nKeyedNetGroupIn=*/0, /*nLocalHostNonceIn=*/0,
                      CAddress{}, /*addrNameIn=*/"active-descendant",
                      ConnectionType::OUTBOUND_FULL_RELAY,
                      /*inbound_onion=*/false, /*network_key=*/0};
    CNode parked_peer{/*id=*/72, /*sock=*/nullptr, CAddress{},
                      /*nKeyedNetGroupIn=*/0, /*nLocalHostNonceIn=*/0,
                      CAddress{}, /*addrNameIn=*/"parked-divergent",
                      ConnectionType::OUTBOUND_FULL_RELAY,
                      /*inbound_onion=*/false, /*network_key=*/0};
    connman.Handshake(active_peer, /*successfully_connected=*/true, services,
                      services, PROTOCOL_VERSION, /*relay_txs=*/true);
    connman.Handshake(parked_peer, /*successfully_connected=*/true, services,
                      services, PROTOCOL_VERSION, /*relay_txs=*/true);
    connman.FlushSendBuffer(active_peer);
    connman.FlushSendBuffer(parked_peer);
    struct FinalizePeers {
        PeerManager& peerman;
        CNode& active_peer;
        CNode& parked_peer;
        ~FinalizePeers()
        {
            peerman.FinalizeNode(active_peer);
            peerman.FinalizeNode(parked_peer);
        }
    } finalize{peerman, active_peer, parked_peer};

    auto advertise = [&](CNode& peer, const uint256& hash) {
        std::vector<CInv> inv{{MSG_BLOCK, hash}};
        BOOST_REQUIRE(connman.ReceiveMsgFrom(
            peer, NetMsg::Make(NetMsgType::INV, inv)));
        peer.fPauseSend = false;
        (void)connman.ProcessMessagesOnce(peer);
        connman.FlushSendBuffer(peer);
    };
    advertise(active_peer, active_child->GetBlockHash());
    advertise(parked_peer, parked_tip->GetBlockHash());

    BOOST_CHECK(peerman.SendMessages(&parked_peer));
    BOOST_CHECK(peerman.SendMessages(&active_peer));
    CNodeStateStats active_stats;
    CNodeStateStats parked_stats;
    BOOST_REQUIRE(peerman.GetNodeStateStats(active_peer.GetId(), active_stats));
    BOOST_REQUIRE(peerman.GetNodeStateStats(parked_peer.GetId(), parked_stats));
    BOOST_CHECK(parked_stats.vHeightInFlight.empty());
    BOOST_CHECK(!HasQueuedMessageType(parked_peer, NetMsgType::GETDATA));
    BOOST_CHECK(!active_stats.vHeightInFlight.empty() ||
                HasQueuedMessageType(active_peer, NetMsgType::GETDATA));
}

// GETMMATTEST must reach the signer archive, trusted mirrors, and consensus
// nodes that keep the attestation store. Ordinary NODE_NETWORK miners (no
// CONSENSUS/ARCHIVE/MIRROR bit) are skipped so miss-backoff is not burned
// on not_serving.
BOOST_AUTO_TEST_CASE(getmmattest_skips_non_serving_peers)
{
    LOCK(NetEventsInterface::g_msgproc_mutex);

    node::matmul_trusted::ResetForTest();
    CKey signer;
    signer.MakeNewKey(/*fCompressed=*/true);
    matmul::trusted::StoreConfig config;
    config.chain_id = uint256::FromHex(std::string(64, '1')).value();
    config.replay_authority_context =
        uint256::FromHex(std::string(64, '2')).value();
    config.trusted_signers = {signer.GetPubKey()};
    config.threshold = 1;
    std::string error;
    BOOST_REQUIRE(node::matmul_trusted::Configure(
        std::move(config), /*trusted_mirror=*/true, /*serve=*/false,
        std::chrono::milliseconds{50}, error));
    BOOST_REQUIRE(node::matmul_trusted::IsTrustedMirror());
    struct MirrorReset {
        ~MirrorReset() { node::matmul_trusted::ResetForTest(); }
    } mirror_reset;

    ConnmanTestMsg& connman = static_cast<ConnmanTestMsg&>(*m_node.connman);
    PeerManager& peerman = *m_node.peerman;

    const ServiceFlags archive_services{ServiceFlags(
        NODE_NETWORK | NODE_WITNESS | NODE_MATMUL_CONSENSUS |
        NODE_MATMUL_ATTESTATION_ARCHIVE)};
    const ServiceFlags miner_services{ServiceFlags(
        NODE_NETWORK | NODE_WITNESS)};
    const ServiceFlags consensus_services{ServiceFlags(
        NODE_NETWORK | NODE_WITNESS | NODE_MATMUL_CONSENSUS)};
    const ServiceFlags mirror_services{ServiceFlags(
        NODE_NETWORK | NODE_WITNESS | NODE_MATMUL_TRUSTED_MIRROR |
        NODE_ATTESTED_UTXO_SNAPSHOT)};

    CNode archive{/*id=*/71,
                  /*sock=*/nullptr,
                  CAddress{},
                  /*nKeyedNetGroupIn=*/0,
                  /*nLocalHostNonceIn=*/0,
                  CAddress{},
                  /*addrNameIn=*/"attestation-archive",
                  ConnectionType::OUTBOUND_FULL_RELAY,
                  /*inbound_onion=*/false,
                  /*network_key=*/0};
    CNode miner{/*id=*/72,
                /*sock=*/nullptr,
                CAddress{},
                /*nKeyedNetGroupIn=*/0,
                /*nLocalHostNonceIn=*/0,
                CAddress{},
                /*addrNameIn=*/"ordinary-miner",
                ConnectionType::OUTBOUND_FULL_RELAY,
                /*inbound_onion=*/false,
                /*network_key=*/0};
    CNode mirror{/*id=*/73,
                 /*sock=*/nullptr,
                 CAddress{},
                 /*nKeyedNetGroupIn=*/0,
                 /*nLocalHostNonceIn=*/0,
                 CAddress{},
                 /*addrNameIn=*/"trusted-mirror",
                 ConnectionType::OUTBOUND_FULL_RELAY,
                 /*inbound_onion=*/false,
                 /*network_key=*/0};
    CNode consensus_peer{/*id=*/74,
                    /*sock=*/nullptr,
                    CAddress{},
                    /*nKeyedNetGroupIn=*/0,
                    /*nLocalHostNonceIn=*/0,
                    CAddress{},
                    /*addrNameIn=*/"consensus-store",
                    ConnectionType::OUTBOUND_FULL_RELAY,
                    /*inbound_onion=*/false,
                    /*network_key=*/0};
    connman.Handshake(archive, /*successfully_connected=*/true,
                      archive_services, archive_services, PROTOCOL_VERSION,
                      /*relay_txs=*/true);
    connman.Handshake(miner, /*successfully_connected=*/true, miner_services,
                      miner_services, PROTOCOL_VERSION, /*relay_txs=*/true);
    connman.Handshake(mirror, /*successfully_connected=*/true, mirror_services,
                      mirror_services, PROTOCOL_VERSION, /*relay_txs=*/true);
    connman.Handshake(consensus_peer, /*successfully_connected=*/true,
                      consensus_services, consensus_services, PROTOCOL_VERSION,
                      /*relay_txs=*/true);
    connman.AddTestNode(archive);
    connman.AddTestNode(miner);
    connman.AddTestNode(mirror);
    connman.AddTestNode(consensus_peer);
    connman.FlushSendBuffer(archive);
    connman.FlushSendBuffer(miner);
    connman.FlushSendBuffer(mirror);
    connman.FlushSendBuffer(consensus_peer);
    struct FinalizePeers {
        ConnmanTestMsg& connman;
        PeerManager& peerman;
        CNode& first;
        CNode& second;
        CNode& third;
        CNode& fourth;
        ~FinalizePeers()
        {
            peerman.FinalizeNode(first);
            peerman.FinalizeNode(second);
            peerman.FinalizeNode(third);
            peerman.FinalizeNode(fourth);
            connman.RemoveTestNode(first);
            connman.RemoveTestNode(second);
            connman.RemoveTestNode(third);
            connman.RemoveTestNode(fourth);
        }
    } finalize{connman, peerman, archive, miner, mirror, consensus_peer};

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
    const int32_t saved_coupled = consensus.nMatMulRCCoupledHeight;
    struct RestoreHeights {
        Consensus::Params& params;
        int32_t rc;
        int32_t v4;
        int32_t bmx4c;
        int32_t drlt;
        int32_t coupled;
        ~RestoreHeights()
        {
            params.nMatMulRCHeight = rc;
            params.nMatMulV4Height = v4;
            params.nMatMulBMX4CHeight = bmx4c;
            params.nMatMulDRLTHeight = drlt;
            params.nMatMulRCCoupledHeight = coupled;
        }
    } restore_heights{consensus, saved_rc, saved_v4, saved_bmx4c, saved_drlt,
                      saved_coupled};

    consensus.nMatMulV4Height = tip->nHeight;
    consensus.nMatMulBMX4CHeight = tip->nHeight;
    consensus.nMatMulDRLTHeight = std::numeric_limits<int32_t>::max();
    consensus.nMatMulRCHeight = tip->nHeight;
    consensus.nMatMulRCCoupledHeight = std::numeric_limits<int32_t>::max();
    peerman.SetBestBlock(tip->nHeight, std::chrono::seconds{tip->GetBlockTime()});
    BOOST_REQUIRE(consensus.IsMatMulTrustedReplayAttestationActive(tip->nHeight));
    BOOST_REQUIRE(
        consensus.IsMatMulTrustedReplayAttestationActive(tip->nHeight + 1));

    CBlock our_next = node::BlockAssembler{
        m_node.chainman->ActiveChainstate(), nullptr, {}, m_node}
                          .CreateNewBlock()
                          ->block;
    our_next.hashMerkleRoot = BlockMerkleRoot(our_next);
    BOOST_REQUIRE(MineHeaderForConsensus(
        our_next, tip->nHeight + 1, m_node.chainman->GetConsensus(), 5'000'000,
        tip->GetMedianTimePast()));
    std::vector<CBlock> our_headers{CBlock{our_next.GetBlockHeader()}};
    auto archive_msg{
        NetMsg::Make(NetMsgType::HEADERS, TX_WITH_WITNESS(our_headers))};
    BOOST_REQUIRE(connman.ReceiveMsgFrom(archive, std::move(archive_msg)));
    archive.fPauseSend = false;
    (void)connman.ProcessMessagesOnce(archive);

    BOOST_CHECK(peerman.SendMessages(&archive));
    BOOST_CHECK(peerman.SendMessages(&miner));
    BOOST_CHECK(peerman.SendMessages(&mirror));
    BOOST_CHECK(peerman.SendMessages(&consensus_peer));

    BOOST_CHECK(HasQueuedMessageType(archive, NetMsgType::GETMMATTEST));
    BOOST_CHECK(!HasQueuedMessageType(miner, NetMsgType::GETMMATTEST));
    BOOST_CHECK(HasQueuedMessageType(mirror, NetMsgType::GETMMATTEST));
    BOOST_CHECK(HasQueuedMessageType(consensus_peer, NetMsgType::GETMMATTEST));
}

// Qualifier on 5bc1e3d4: a trusted mirror whose tip is still the last
// pre-activation block sent 0 GETMMATTEST, so ConnectTip deferred the
// activation-height body forever. Skipping ExactReplay GPU on configured
// nodes must not skip attestation acquisition for that tip-child.
BOOST_AUTO_TEST_CASE(getmmattest_pre_activation_tip_requests_child)
{
    LOCK(NetEventsInterface::g_msgproc_mutex);

    node::matmul_trusted::ResetForTest();
    CKey signer;
    signer.MakeNewKey(/*fCompressed=*/true);
    matmul::trusted::StoreConfig config;
    config.chain_id = uint256::FromHex(std::string(64, '1')).value();
    config.replay_authority_context =
        uint256::FromHex(std::string(64, '2')).value();
    config.trusted_signers = {signer.GetPubKey()};
    config.threshold = 1;
    std::string error;
    BOOST_REQUIRE(node::matmul_trusted::Configure(
        std::move(config), /*trusted_mirror=*/true, /*serve=*/false,
        std::chrono::milliseconds{50}, error));
    BOOST_REQUIRE(node::matmul_trusted::IsTrustedMirror());
    struct MirrorReset {
        ~MirrorReset() { node::matmul_trusted::ResetForTest(); }
    } mirror_reset;

    ConnmanTestMsg& connman = static_cast<ConnmanTestMsg&>(*m_node.connman);
    PeerManager& peerman = *m_node.peerman;

    const ServiceFlags archive_services{ServiceFlags(
        NODE_NETWORK | NODE_WITNESS | NODE_MATMUL_CONSENSUS |
        NODE_MATMUL_ATTESTATION_ARCHIVE)};
    CNode archive{/*id=*/81,
                  /*sock=*/nullptr,
                  CAddress{},
                  /*nKeyedNetGroupIn=*/0,
                  /*nLocalHostNonceIn=*/0,
                  CAddress{},
                  /*addrNameIn=*/"pre-activation-archive",
                  ConnectionType::OUTBOUND_FULL_RELAY,
                  /*inbound_onion=*/false,
                  /*network_key=*/0};
    connman.Handshake(archive, /*successfully_connected=*/true,
                      archive_services, archive_services, PROTOCOL_VERSION,
                      /*relay_txs=*/true);
    connman.AddTestNode(archive);
    connman.FlushSendBuffer(archive);
    struct FinalizePeer {
        ConnmanTestMsg& connman;
        PeerManager& peerman;
        CNode& node;
        ~FinalizePeer()
        {
            peerman.FinalizeNode(node);
            connman.RemoveTestNode(node);
        }
    } finalize{connman, peerman, archive};

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
    const int32_t saved_coupled = consensus.nMatMulRCCoupledHeight;
    struct RestoreHeights {
        Consensus::Params& params;
        int32_t rc;
        int32_t v4;
        int32_t bmx4c;
        int32_t drlt;
        int32_t coupled;
        ~RestoreHeights()
        {
            params.nMatMulRCHeight = rc;
            params.nMatMulV4Height = v4;
            params.nMatMulBMX4CHeight = bmx4c;
            params.nMatMulDRLTHeight = drlt;
            params.nMatMulRCCoupledHeight = coupled;
        }
    } restore_heights{consensus, saved_rc, saved_v4, saved_bmx4c, saved_drlt,
                      saved_coupled};

    const int32_t activation{tip->nHeight + 1};
    consensus.nMatMulV4Height = activation;
    consensus.nMatMulBMX4CHeight = activation;
    consensus.nMatMulDRLTHeight = std::numeric_limits<int32_t>::max();
    consensus.nMatMulRCHeight = activation;
    consensus.nMatMulRCCoupledHeight = std::numeric_limits<int32_t>::max();
    peerman.SetBestBlock(tip->nHeight, std::chrono::seconds{tip->GetBlockTime()});
    BOOST_REQUIRE(!consensus.IsMatMulTrustedReplayAttestationActive(tip->nHeight));
    BOOST_REQUIRE(
        consensus.IsMatMulTrustedReplayAttestationActive(activation));

    CBlock our_next = node::BlockAssembler{
        m_node.chainman->ActiveChainstate(), nullptr, {}, m_node}
                          .CreateNewBlock()
                          ->block;
    our_next.hashMerkleRoot = BlockMerkleRoot(our_next);
    BOOST_REQUIRE(MineHeaderForConsensus(
        our_next, activation, m_node.chainman->GetConsensus(), 5'000'000,
        tip->GetMedianTimePast()));
    std::vector<CBlock> our_headers{CBlock{our_next.GetBlockHeader()}};
    auto archive_msg{
        NetMsg::Make(NetMsgType::HEADERS, TX_WITH_WITNESS(our_headers))};
    BOOST_REQUIRE(connman.ReceiveMsgFrom(archive, std::move(archive_msg)));
    archive.fPauseSend = false;
    (void)connman.ProcessMessagesOnce(archive);

    BOOST_CHECK(peerman.SendMessages(&archive));
    BOOST_CHECK(HasQueuedMessageType(archive, NetMsgType::GETMMATTEST));
}

// Body-connect for the independent consensus verifier (IsConfigured, not a
// trusted mirror, no local signer) is covered by the 4th node in
// feature_matmul_trusted_mirrors.py. This case only documents that Profile-1
// still queues GETMMATTEST for a tip-child header under that role
// (qualifier: d43eea4a collapsed ExactReplay+attest into IsConfigured and
// consensus verifiers acquired neither).
BOOST_AUTO_TEST_CASE(getmmattest_consensus_verifier_pre_activation_tip_requests_child)
{
    LOCK(NetEventsInterface::g_msgproc_mutex);

    node::matmul_trusted::ResetForTest();
    CKey signer;
    signer.MakeNewKey(/*fCompressed=*/true);
    matmul::trusted::StoreConfig config;
    config.chain_id = uint256::FromHex(std::string(64, '1')).value();
    config.replay_authority_context =
        uint256::FromHex(std::string(64, '2')).value();
    config.trusted_signers = {signer.GetPubKey()};
    config.threshold = 1;
    std::string error;
    BOOST_REQUIRE(node::matmul_trusted::Configure(
        std::move(config), /*trusted_mirror=*/false, /*serve=*/false,
        std::chrono::milliseconds{50}, error));
    BOOST_REQUIRE(!node::matmul_trusted::IsTrustedMirror());
    BOOST_REQUIRE(node::matmul_trusted::IsConfigured());
    BOOST_REQUIRE(!node::matmul_trusted::HasLocalSigner());
    struct VerifierReset {
        ~VerifierReset() { node::matmul_trusted::ResetForTest(); }
    } verifier_reset;

    ConnmanTestMsg& connman = static_cast<ConnmanTestMsg&>(*m_node.connman);
    PeerManager& peerman = *m_node.peerman;

    const ServiceFlags archive_services{ServiceFlags(
        NODE_NETWORK | NODE_WITNESS | NODE_MATMUL_CONSENSUS |
        NODE_MATMUL_ATTESTATION_ARCHIVE)};
    CNode archive{/*id=*/82,
                  /*sock=*/nullptr,
                  CAddress{},
                  /*nKeyedNetGroupIn=*/0,
                  /*nLocalHostNonceIn=*/0,
                  CAddress{},
                  /*addrNameIn=*/"pre-activation-verifier-archive",
                  ConnectionType::OUTBOUND_FULL_RELAY,
                  /*inbound_onion=*/false,
                  /*network_key=*/0};
    connman.Handshake(archive, /*successfully_connected=*/true,
                      archive_services, archive_services, PROTOCOL_VERSION,
                      /*relay_txs=*/true);
    connman.AddTestNode(archive);
    connman.FlushSendBuffer(archive);
    struct FinalizePeer {
        ConnmanTestMsg& connman;
        PeerManager& peerman;
        CNode& node;
        ~FinalizePeer()
        {
            peerman.FinalizeNode(node);
            connman.RemoveTestNode(node);
        }
    } finalize{connman, peerman, archive};

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
    const int32_t saved_coupled = consensus.nMatMulRCCoupledHeight;
    struct RestoreHeights {
        Consensus::Params& params;
        int32_t rc;
        int32_t v4;
        int32_t bmx4c;
        int32_t drlt;
        int32_t coupled;
        ~RestoreHeights()
        {
            params.nMatMulRCHeight = rc;
            params.nMatMulV4Height = v4;
            params.nMatMulBMX4CHeight = bmx4c;
            params.nMatMulDRLTHeight = drlt;
            params.nMatMulRCCoupledHeight = coupled;
        }
    } restore_heights{consensus, saved_rc, saved_v4, saved_bmx4c, saved_drlt,
                      saved_coupled};

    const int32_t activation{tip->nHeight + 1};
    consensus.nMatMulV4Height = activation;
    consensus.nMatMulBMX4CHeight = activation;
    consensus.nMatMulDRLTHeight = std::numeric_limits<int32_t>::max();
    consensus.nMatMulRCHeight = activation;
    consensus.nMatMulRCCoupledHeight = std::numeric_limits<int32_t>::max();
    peerman.SetBestBlock(tip->nHeight, std::chrono::seconds{tip->GetBlockTime()});
    BOOST_REQUIRE(!consensus.IsMatMulTrustedReplayAttestationActive(tip->nHeight));
    BOOST_REQUIRE(
        consensus.IsMatMulTrustedReplayAttestationActive(activation));

    CBlock our_next = node::BlockAssembler{
        m_node.chainman->ActiveChainstate(), nullptr, {}, m_node}
                          .CreateNewBlock()
                          ->block;
    our_next.hashMerkleRoot = BlockMerkleRoot(our_next);
    BOOST_REQUIRE(MineHeaderForConsensus(
        our_next, activation, m_node.chainman->GetConsensus(), 5'000'000,
        tip->GetMedianTimePast()));
    std::vector<CBlock> our_headers{CBlock{our_next.GetBlockHeader()}};
    auto archive_msg{
        NetMsg::Make(NetMsgType::HEADERS, TX_WITH_WITNESS(our_headers))};
    BOOST_REQUIRE(connman.ReceiveMsgFrom(archive, std::move(archive_msg)));
    archive.fPauseSend = false;
    (void)connman.ProcessMessagesOnce(archive);

    BOOST_CHECK(peerman.SendMessages(&archive));
    BOOST_CHECK(HasQueuedMessageType(archive, NetMsgType::GETMMATTEST));
}

BOOST_AUTO_TEST_CASE(getdata_unknown_block_sends_notfound)
{
    LOCK(NetEventsInterface::g_msgproc_mutex);

    ConnmanTestMsg& connman{static_cast<ConnmanTestMsg&>(*m_node.connman)};
    PeerManager& peerman{*Assert(m_node.peerman)};
    const ServiceFlags services{ServiceFlags(NODE_NETWORK | NODE_WITNESS)};
    CNode peer{/*id=*/91, /*sock=*/nullptr, CAddress{},
               /*nKeyedNetGroupIn=*/0, /*nLocalHostNonceIn=*/0,
               CAddress{}, /*addrNameIn=*/"notfound-peer",
               ConnectionType::OUTBOUND_FULL_RELAY,
               /*inbound_onion=*/false, /*network_key=*/0};
    connman.Handshake(peer, /*successfully_connected=*/true, services,
                      services, PROTOCOL_VERSION, /*relay_txs=*/true);
    connman.FlushSendBuffer(peer);
    struct FinalizePeer {
        PeerManager& peerman;
        ConnmanTestMsg& connman;
        CNode& peer;
        ~FinalizePeer()
        {
            peerman.FinalizeNode(peer);
            connman.RemoveTestNode(peer);
        }
    } finalize{peerman, connman, peer};

    std::vector<CInv> inv{{MSG_BLOCK | MSG_WITNESS_FLAG, uint256::ONE}};
    BOOST_REQUIRE(connman.ReceiveMsgFrom(
        peer, NetMsg::Make(NetMsgType::GETDATA, inv)));
    peer.fPauseSend = false;
    (void)connman.ProcessMessagesOnce(peer);
    BOOST_CHECK(HasQueuedMessageType(peer, NetMsgType::NOTFOUND));
}

BOOST_AUTO_TEST_CASE(catchup_requests_only_lowest_hole_and_fails_over_silent_peer)
{
    LOCK(NetEventsInterface::g_msgproc_mutex);

    ChainstateManager& chainman{*Assert(m_node.chainman)};
    PeerManager& peerman{*Assert(m_node.peerman)};
    ConnmanTestMsg& connman{static_cast<ConnmanTestMsg&>(*m_node.connman)};
    const CBlockIndex* starting_tip{
        WITH_LOCK(::cs_main, return chainman.ActiveChain().Tip())};
    BOOST_REQUIRE(starting_tip != nullptr);
    SetMockTime(std::chrono::seconds{starting_tip->GetBlockTime() + 3600});
    BOOST_REQUIRE(!chainman.IsInitialBlockDownload());

    auto make_header = [&](const CBlockIndex& prev, unsigned char tag) {
        CBlock block;
        block.SetNull();
        block.hashPrevBlock = prev.GetBlockHash();
        block.hashMerkleRoot = uint256::FromHex(
            std::string(62, '0') + strprintf("%02x", tag)).value();
        block.nTime = prev.GetBlockTime() + 1;
        block.nBits = prev.nBits;
        block.nVersion = VERSIONBITS_TOP_BITS;
        BOOST_REQUIRE(MineHeaderForConsensus(
            block, prev.nHeight + 1, chainman.GetConsensus(), 5'000'000,
            prev.GetMedianTimePast()));
        BlockValidationState state;
        const CBlockHeader header{block.GetBlockHeader()};
        BOOST_REQUIRE_MESSAGE(chainman.ProcessNewBlockHeaders(
            {{header}}, /*min_pow_checked=*/true, state), state.ToString());
        CBlockIndex* index{WITH_LOCK(
            ::cs_main,
            return chainman.m_blockman.LookupBlockIndex(block.GetHash()))};
        BOOST_REQUIRE(index != nullptr);
        return index;
    };

    const CBlockIndex* tip{
        WITH_LOCK(::cs_main, return chainman.ActiveChain().Tip())};
    std::vector<CBlockIndex*> headers;
    const CBlockIndex* walk{tip};
    for (unsigned char tag = 0xc1; tag <= 0xc6; ++tag) {
        CBlockIndex* nxt{make_header(*walk, tag)};
        headers.push_back(nxt);
        walk = nxt;
    }
    BOOST_REQUIRE_EQUAL(headers.size(), 6U);
    BOOST_CHECK_EQUAL(
        WITH_LOCK(::cs_main, return chainman.ActiveChain().Tip()->nHeight),
        tip->nHeight);
    BOOST_CHECK_EQUAL(
        WITH_LOCK(::cs_main, return chainman.m_best_header->nHeight),
        tip->nHeight + 6);

    const ServiceFlags services{ServiceFlags(NODE_NETWORK | NODE_WITNESS)};
    CNode silent{/*id=*/92, /*sock=*/nullptr, CAddress{},
                 /*nKeyedNetGroupIn=*/0, /*nLocalHostNonceIn=*/0,
                 CAddress{}, /*addrNameIn=*/"catchup-silent",
                 ConnectionType::OUTBOUND_FULL_RELAY,
                 /*inbound_onion=*/false, /*network_key=*/0};
    CNode second{/*id=*/93, /*sock=*/nullptr, CAddress{},
                 /*nKeyedNetGroupIn=*/1, /*nLocalHostNonceIn=*/0,
                 CAddress{}, /*addrNameIn=*/"catchup-second",
                 ConnectionType::OUTBOUND_FULL_RELAY,
                 /*inbound_onion=*/false, /*network_key=*/0};
    connman.Handshake(silent, /*successfully_connected=*/true, services,
                      services, PROTOCOL_VERSION, /*relay_txs=*/true);
    connman.Handshake(second, /*successfully_connected=*/true, services,
                      services, PROTOCOL_VERSION, /*relay_txs=*/true);
    connman.FlushSendBuffer(silent);
    connman.FlushSendBuffer(second);
    struct FinalizePeers {
        PeerManager& peerman;
        ConnmanTestMsg& connman;
        CNode& silent;
        CNode& second;
        ~FinalizePeers()
        {
            peerman.FinalizeNode(silent);
            peerman.FinalizeNode(second);
            connman.RemoveTestNode(silent);
            connman.RemoveTestNode(second);
        }
    } finalize{peerman, connman, silent, second};

    auto advertise = [&](CNode& peer) {
        std::vector<CBlock> hdrs;
        hdrs.reserve(headers.size());
        {
            LOCK(::cs_main);
            for (CBlockIndex* idx : headers) {
                hdrs.emplace_back(idx->GetBlockHeader());
            }
        }
        BOOST_REQUIRE(connman.ReceiveMsgFrom(
            peer, NetMsg::Make(NetMsgType::HEADERS, TX_WITH_WITNESS(hdrs))));
        peer.fPauseSend = false;
        (void)connman.ProcessMessagesOnce(peer);
    };
    advertise(silent);
    advertise(second);

    BOOST_CHECK(peerman.SendMessages(&silent));
    CNodeStateStats silent_stats;
    BOOST_REQUIRE(peerman.GetNodeStateStats(silent.GetId(), silent_stats));
    BOOST_REQUIRE_EQUAL(silent_stats.vHeightInFlight.size(), 1U);
    BOOST_CHECK_EQUAL(silent_stats.vHeightInFlight.front(), tip->nHeight + 1);
    BOOST_CHECK(HasQueuedMessageType(silent, NetMsgType::GETDATA));

    BOOST_CHECK(peerman.SendMessages(&second));
    CNodeStateStats second_stats;
    BOOST_REQUIRE(peerman.GetNodeStateStats(second.GetId(), second_stats));
    BOOST_REQUIRE_EQUAL(second_stats.vHeightInFlight.size(), 1U);
    BOOST_CHECK_EQUAL(second_stats.vHeightInFlight.front(), tip->nHeight + 1);

    SetMockTime(std::chrono::seconds{GetTime() + 16});
    BOOST_CHECK(peerman.SendMessages(&silent));
    CNodeStateStats silent_after;
    BOOST_REQUIRE(peerman.GetNodeStateStats(silent.GetId(), silent_after));
    BOOST_CHECK(silent_after.vHeightInFlight.empty());
    BOOST_CHECK(!silent.fDisconnect);
    NeutralizeUnconnectedHeaders(chainman);
    peerman.ResetMatMulVerifyAdmissionForTest();
}

BOOST_AUTO_TEST_CASE(catchup_direct_fetch_requests_only_lowest_hole)
{
    LOCK(NetEventsInterface::g_msgproc_mutex);

    ChainstateManager& chainman{*Assert(m_node.chainman)};
    PeerManager& peerman{*Assert(m_node.peerman)};
    ConnmanTestMsg& connman{static_cast<ConnmanTestMsg&>(*m_node.connman)};
    const CBlockIndex* starting_tip{
        WITH_LOCK(::cs_main, return chainman.ActiveChain().Tip())};
    BOOST_REQUIRE(starting_tip != nullptr);
    // Tip time close enough that CanDirectFetch is true (existing catch-up
    // test uses +3600 so HeadersDirectFetch is skipped).
    SetMockTime(std::chrono::seconds{starting_tip->GetBlockTime() + 1});
    BOOST_REQUIRE(!chainman.IsInitialBlockDownload());

    auto make_header = [&](const CBlockIndex& prev, unsigned char tag) {
        CBlock block;
        block.SetNull();
        block.hashPrevBlock = prev.GetBlockHash();
        block.hashMerkleRoot = uint256::FromHex(
            std::string(62, '0') + strprintf("%02x", tag)).value();
        block.nTime = prev.GetBlockTime() + 1;
        block.nBits = prev.nBits;
        block.nVersion = VERSIONBITS_TOP_BITS;
        BOOST_REQUIRE(MineHeaderForConsensus(
            block, prev.nHeight + 1, chainman.GetConsensus(), 5'000'000,
            prev.GetMedianTimePast()));
        BlockValidationState state;
        const CBlockHeader header{block.GetBlockHeader()};
        BOOST_REQUIRE_MESSAGE(chainman.ProcessNewBlockHeaders(
            {{header}}, /*min_pow_checked=*/true, state), state.ToString());
        CBlockIndex* index{WITH_LOCK(
            ::cs_main,
            return chainman.m_blockman.LookupBlockIndex(block.GetHash()))};
        BOOST_REQUIRE(index != nullptr);
        return index;
    };

    const CBlockIndex* tip{
        WITH_LOCK(::cs_main, return chainman.ActiveChain().Tip())};
    std::vector<CBlockIndex*> headers;
    const CBlockIndex* walk{tip};
    for (unsigned char tag = 0xd1; tag <= 0xd6; ++tag) {
        CBlockIndex* nxt{make_header(*walk, tag)};
        headers.push_back(nxt);
        walk = nxt;
    }
    BOOST_REQUIRE_EQUAL(headers.size(), 6U);

    const ServiceFlags services{ServiceFlags(NODE_NETWORK | NODE_WITNESS)};
    CNode peer{/*id=*/94, /*sock=*/nullptr, CAddress{},
               /*nKeyedNetGroupIn=*/0, /*nLocalHostNonceIn=*/0,
               CAddress{}, /*addrNameIn=*/"directfetch-catchup",
               ConnectionType::OUTBOUND_FULL_RELAY,
               /*inbound_onion=*/false, /*network_key=*/0};
    connman.Handshake(peer, /*successfully_connected=*/true, services,
                      services, PROTOCOL_VERSION, /*relay_txs=*/true);
    connman.FlushSendBuffer(peer);
    struct FinalizePeer {
        PeerManager& peerman;
        ConnmanTestMsg& connman;
        CNode& peer;
        ~FinalizePeer()
        {
            peerman.FinalizeNode(peer);
            connman.RemoveTestNode(peer);
        }
    } finalize{peerman, connman, peer};

    std::vector<CBlock> hdrs;
    hdrs.reserve(headers.size());
    {
        LOCK(::cs_main);
        for (CBlockIndex* idx : headers) {
            hdrs.emplace_back(idx->GetBlockHeader());
        }
    }
    BOOST_REQUIRE(connman.ReceiveMsgFrom(
        peer, NetMsg::Make(NetMsgType::HEADERS, TX_WITH_WITNESS(hdrs))));
    peer.fPauseSend = false;
    (void)connman.ProcessMessagesOnce(peer);

    // Headers were already in the index (ProcessNewBlockHeaders above), so
    // #107 treats the P2P batch as already-known ancestors and skips
    // HeadersDirectFetch. That is the production path when another peer
    // (or this fixture) accepted the headers first: do not re-process, do
    // not weaken the duplicate-header flood bound. Bodies are still
    // requested from SendMessages once pindexBestKnownBlock is updated.
    CNodeStateStats after_headers;
    BOOST_REQUIRE(peerman.GetNodeStateStats(peer.GetId(), after_headers));
    BOOST_CHECK(after_headers.vHeightInFlight.empty());
    BOOST_CHECK(!peer.fDisconnect);

    BOOST_CHECK(peerman.SendMessages(&peer));
    CNodeStateStats after_send;
    BOOST_REQUIRE(peerman.GetNodeStateStats(peer.GetId(), after_send));
    BOOST_REQUIRE_EQUAL(after_send.vHeightInFlight.size(), 1U);
    BOOST_CHECK_EQUAL(after_send.vHeightInFlight.front(), tip->nHeight + 1);
    NeutralizeUnconnectedHeaders(chainman);
    peerman.ResetMatMulVerifyAdmissionForTest();
}

// Live 2026-08-15: assumeutxo-189307 consensus nodes latched IBD false (full
// chainwork, tip inside 24h) with 517 followed headers still body-less, then
// sat in 1-wide/15s catch-up until every peer timed out (synced_blocks=-1).
// Ahead >= 32 must keep the IBD download window.
BOOST_AUTO_TEST_CASE(long_catchup_uses_wide_download_window)
{
    LOCK(NetEventsInterface::g_msgproc_mutex);

    ChainstateManager& chainman{*Assert(m_node.chainman)};
    PeerManager& peerman{*Assert(m_node.peerman)};
    ConnmanTestMsg& connman{static_cast<ConnmanTestMsg&>(*m_node.connman)};
    const CBlockIndex* starting_tip{
        WITH_LOCK(::cs_main, return chainman.ActiveChain().Tip())};
    BOOST_REQUIRE(starting_tip != nullptr);
    SetMockTime(std::chrono::seconds{starting_tip->GetBlockTime() + 3600});
    BOOST_REQUIRE(!chainman.IsInitialBlockDownload());

    auto make_header = [&](const CBlockIndex& prev, unsigned int tag) {
        CBlock block;
        block.SetNull();
        block.hashPrevBlock = prev.GetBlockHash();
        block.hashMerkleRoot = uint256::FromHex(
            std::string(60, '0') + strprintf("%04x", tag)).value();
        block.nTime = prev.GetBlockTime() + 1;
        block.nBits = prev.nBits;
        block.nVersion = VERSIONBITS_TOP_BITS;
        BOOST_REQUIRE(MineHeaderForConsensus(
            block, prev.nHeight + 1, chainman.GetConsensus(), 5'000'000,
            prev.GetMedianTimePast()));
        BlockValidationState state;
        const CBlockHeader header{block.GetBlockHeader()};
        BOOST_REQUIRE_MESSAGE(chainman.ProcessNewBlockHeaders(
            {{header}}, /*min_pow_checked=*/true, state), state.ToString());
        CBlockIndex* index{WITH_LOCK(
            ::cs_main,
            return chainman.m_blockman.LookupBlockIndex(block.GetHash()))};
        BOOST_REQUIRE(index != nullptr);
        return index;
    };

    const CBlockIndex* tip{
        WITH_LOCK(::cs_main, return chainman.ActiveChain().Tip())};
    std::vector<CBlockIndex*> headers;
    const CBlockIndex* walk{tip};
    // CATCHUP_NARROW_MAX_AHEAD is 32; this must stay at/above that bound.
    constexpr int kLongCatchupHeaders = 32;
    for (int i = 0; i < kLongCatchupHeaders; ++i) {
        CBlockIndex* nxt{make_header(*walk, 0xe00u + static_cast<unsigned int>(i))};
        headers.push_back(nxt);
        walk = nxt;
    }
    BOOST_REQUIRE_EQUAL(headers.size(), static_cast<size_t>(kLongCatchupHeaders));
    BOOST_CHECK_EQUAL(
        WITH_LOCK(::cs_main, return chainman.m_best_header->nHeight),
        tip->nHeight + kLongCatchupHeaders);

    const ServiceFlags services{ServiceFlags(NODE_NETWORK | NODE_WITNESS)};
    CNode seed{/*id=*/95, /*sock=*/nullptr, CAddress{},
               /*nKeyedNetGroupIn=*/0, /*nLocalHostNonceIn=*/0,
               CAddress{}, /*addrNameIn=*/"long-catchup-seed",
               ConnectionType::OUTBOUND_FULL_RELAY,
               /*inbound_onion=*/false, /*network_key=*/0};
    connman.Handshake(seed, /*successfully_connected=*/true, services,
                      services, PROTOCOL_VERSION, /*relay_txs=*/true);
    connman.FlushSendBuffer(seed);
    struct FinalizeSeed {
        PeerManager& peerman;
        ConnmanTestMsg& connman;
        CNode& seed;
        ~FinalizeSeed()
        {
            peerman.FinalizeNode(seed);
            connman.RemoveTestNode(seed);
        }
    } finalize{peerman, connman, seed};

    std::vector<CBlock> hdrs;
    hdrs.reserve(headers.size());
    {
        LOCK(::cs_main);
        for (CBlockIndex* idx : headers) {
            hdrs.emplace_back(idx->GetBlockHeader());
        }
    }
    BOOST_REQUIRE(connman.ReceiveMsgFrom(
        seed, NetMsg::Make(NetMsgType::HEADERS, TX_WITH_WITNESS(hdrs))));
    seed.fPauseSend = false;
    (void)connman.ProcessMessagesOnce(seed);

    BOOST_CHECK(peerman.SendMessages(&seed));
    CNodeStateStats stats;
    BOOST_REQUIRE(peerman.GetNodeStateStats(seed.GetId(), stats));
    BOOST_REQUIRE_GE(stats.vHeightInFlight.size(), 2U);
    BOOST_CHECK_EQUAL(stats.vHeightInFlight.front(), tip->nHeight + 1);
    BOOST_CHECK(HasQueuedMessageType(seed, NetMsgType::GETDATA));
    NeutralizeUnconnectedHeaders(chainman);
    peerman.ResetMatMulVerifyAdmissionForTest();
}

BOOST_AUTO_TEST_CASE(have_data_unconnected_does_not_issue_descendant_getdata)
{
    LOCK(NetEventsInterface::g_msgproc_mutex);

    ChainstateManager& chainman{*Assert(m_node.chainman)};
    PeerManager& peerman{*Assert(m_node.peerman)};
    ConnmanTestMsg& connman{static_cast<ConnmanTestMsg&>(*m_node.connman)};
    // Fake HAVE_DATA below has no disk bytes. ConnectTip would otherwise
    // FatalError and poison every later case in this shared fixture.
    Assert(m_node.notifications)->m_shutdown_on_fatal_error = false;
    const CBlockIndex* starting_tip{
        WITH_LOCK(::cs_main, return chainman.ActiveChain().Tip())};
    BOOST_REQUIRE(starting_tip != nullptr);
    SetMockTime(std::chrono::seconds{starting_tip->GetBlockTime() + 3600});
    BOOST_REQUIRE(!chainman.IsInitialBlockDownload());

    auto make_header = [&](const CBlockIndex& prev, unsigned char tag) {
        CBlock block;
        block.SetNull();
        block.hashPrevBlock = prev.GetBlockHash();
        block.hashMerkleRoot = uint256::FromHex(
            std::string(62, '0') + strprintf("%02x", tag)).value();
        block.nTime = prev.GetBlockTime() + 1;
        block.nBits = prev.nBits;
        block.nVersion = VERSIONBITS_TOP_BITS;
        BOOST_REQUIRE(MineHeaderForConsensus(
            block, prev.nHeight + 1, chainman.GetConsensus(), 5'000'000,
            prev.GetMedianTimePast()));
        BlockValidationState state;
        const CBlockHeader header{block.GetBlockHeader()};
        BOOST_REQUIRE_MESSAGE(chainman.ProcessNewBlockHeaders(
            {{header}}, /*min_pow_checked=*/true, state), state.ToString());
        CBlockIndex* index{WITH_LOCK(
            ::cs_main,
            return chainman.m_blockman.LookupBlockIndex(block.GetHash()))};
        BOOST_REQUIRE(index != nullptr);
        return index;
    };

    const CBlockIndex* tip{
        WITH_LOCK(::cs_main, return chainman.ActiveChain().Tip())};
    std::vector<CBlockIndex*> headers;
    const CBlockIndex* walk{tip};
    for (unsigned char tag = 0xe1; tag <= 0xe6; ++tag) {
        CBlockIndex* nxt{make_header(*walk, tag)};
        headers.push_back(nxt);
        walk = nxt;
    }
    BOOST_REQUIRE_EQUAL(headers.size(), 6U);

    {
        LOCK(::cs_main);
        // Fake a stored-but-not-connected body. CheckBlockIndex requires
        // HAVE_DATA ⇒ nTx/VALID_TRANSACTIONS and a candidate entry. ConnectTip
        // may log a read failure (no disk bytes); shutdown is disabled so that
        // does not abort the shared fixture. The point of the test is that
        // download selection still refuses descendant getdata.
        headers[0]->nStatus |= BLOCK_HAVE_DATA | BLOCK_VALID_TRANSACTIONS;
        headers[0]->nTx = 1;
        headers[0]->m_chain_tx_count =
            (headers[0]->pprev ? headers[0]->pprev->m_chain_tx_count : 0) + 1;
        chainman.ActiveChainstate().setBlockIndexCandidates.insert(headers[0]);
        BOOST_REQUIRE(!chainman.ActiveChain().Contains(headers[0]));
    }

    const ServiceFlags services{ServiceFlags(NODE_NETWORK | NODE_WITNESS)};
    CNode peer{/*id=*/95, /*sock=*/nullptr, CAddress{},
               /*nKeyedNetGroupIn=*/0, /*nLocalHostNonceIn=*/0,
               CAddress{}, /*addrNameIn=*/"have-data-unconnected",
               ConnectionType::OUTBOUND_FULL_RELAY,
               /*inbound_onion=*/false, /*network_key=*/0};
    connman.Handshake(peer, /*successfully_connected=*/true, services,
                      services, PROTOCOL_VERSION, /*relay_txs=*/true);
    connman.FlushSendBuffer(peer);
    struct FinalizePeer {
        PeerManager& peerman;
        ConnmanTestMsg& connman;
        CNode& peer;
        ~FinalizePeer()
        {
            peerman.FinalizeNode(peer);
            connman.RemoveTestNode(peer);
        }
    } finalize{peerman, connman, peer};

    auto advertise = [&](size_t begin, size_t end) {
        std::vector<CBlock> hdrs;
        hdrs.reserve(end - begin);
        {
            LOCK(::cs_main);
            for (size_t i = begin; i < end; ++i) {
                hdrs.emplace_back(headers[i]->GetBlockHeader());
            }
        }
        BOOST_REQUIRE(connman.ReceiveMsgFrom(
            peer, NetMsg::Make(NetMsgType::HEADERS, TX_WITH_WITNESS(hdrs))));
        peer.fPauseSend = false;
        (void)connman.ProcessMessagesOnce(peer);
    };

    advertise(/*begin=*/0, /*end=*/1);
    BOOST_CHECK(peerman.SendMessages(&peer));
    CNodeStateStats after_have_data;
    BOOST_REQUIRE(peerman.GetNodeStateStats(peer.GetId(), after_have_data));
    BOOST_CHECK_EQUAL(after_have_data.nCommonHeight, tip->nHeight + 1);
    BOOST_CHECK(after_have_data.vHeightInFlight.empty());
    connman.FlushSendBuffer(peer);

    advertise(/*begin=*/0, /*end=*/headers.size());
    BOOST_CHECK(peerman.SendMessages(&peer));
    CNodeStateStats after_descendants;
    BOOST_REQUIRE(peerman.GetNodeStateStats(peer.GetId(), after_descendants));
    BOOST_CHECK(after_descendants.vHeightInFlight.empty());
    BOOST_CHECK(!HasQueuedMessageType(peer, NetMsgType::GETDATA));

    NeutralizeUnconnectedHeaders(chainman);
    peerman.ResetMatMulVerifyAdmissionForTest();
    if (m_node.warnings) {
        m_node.warnings->Unset(node::Warning::FATAL_INTERNAL_ERROR);
    }
    Assert(m_node.notifications)->m_shutdown_on_fatal_error = true;
}

BOOST_AUTO_TEST_CASE(getdata_headers_only_sends_notfound)
{
    LOCK(NetEventsInterface::g_msgproc_mutex);

    ChainstateManager& chainman{*Assert(m_node.chainman)};
    ConnmanTestMsg& connman{static_cast<ConnmanTestMsg&>(*m_node.connman)};
    PeerManager& peerman{*Assert(m_node.peerman)};
    const CBlockIndex* tip{
        WITH_LOCK(::cs_main, return chainman.ActiveChain().Tip())};
    BOOST_REQUIRE(tip != nullptr);

    CBlock block;
    block.SetNull();
    block.hashPrevBlock = tip->GetBlockHash();
    block.hashMerkleRoot = uint256::FromHex(std::string(64, 'a')).value();
    block.nTime = tip->GetBlockTime() + 1;
    block.nBits = tip->nBits;
    block.nVersion = VERSIONBITS_TOP_BITS;
    BOOST_REQUIRE(MineHeaderForConsensus(
        block, tip->nHeight + 1, chainman.GetConsensus(), 5'000'000,
        tip->GetMedianTimePast()));
    BlockValidationState state;
    const CBlockHeader header{block.GetBlockHeader()};
    BOOST_REQUIRE_MESSAGE(chainman.ProcessNewBlockHeaders(
        {{header}}, /*min_pow_checked=*/true, state), state.ToString());
    const uint256 hash{block.GetHash()};
    {
        LOCK(::cs_main);
        const CBlockIndex* idx{chainman.m_blockman.LookupBlockIndex(hash)};
        BOOST_REQUIRE(idx != nullptr);
        BOOST_REQUIRE(!(idx->nStatus & BLOCK_HAVE_DATA));
        BOOST_REQUIRE(!chainman.ActiveChain().Contains(idx));
    }

    const ServiceFlags services{ServiceFlags(NODE_NETWORK | NODE_WITNESS)};
    CNode peer{/*id=*/96, /*sock=*/nullptr, CAddress{},
               /*nKeyedNetGroupIn=*/0, /*nLocalHostNonceIn=*/0,
               CAddress{}, /*addrNameIn=*/"headers-only-notfound",
               ConnectionType::OUTBOUND_FULL_RELAY,
               /*inbound_onion=*/false, /*network_key=*/0};
    connman.Handshake(peer, /*successfully_connected=*/true, services,
                      services, PROTOCOL_VERSION, /*relay_txs=*/true);
    connman.FlushSendBuffer(peer);
    struct FinalizePeer {
        PeerManager& peerman;
        ConnmanTestMsg& connman;
        CNode& peer;
        ~FinalizePeer()
        {
            peerman.FinalizeNode(peer);
            connman.RemoveTestNode(peer);
        }
    } finalize{peerman, connman, peer};

    std::vector<CInv> inv{{MSG_BLOCK | MSG_WITNESS_FLAG, hash}};
    BOOST_REQUIRE(connman.ReceiveMsgFrom(
        peer, NetMsg::Make(NetMsgType::GETDATA, inv)));
    peer.fPauseSend = false;
    (void)connman.ProcessMessagesOnce(peer);
    BOOST_CHECK(HasQueuedMessageType(peer, NetMsgType::NOTFOUND));
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

BOOST_AUTO_TEST_CASE(unrequested_followed_tip_child_persists_without_gpu)
{
    LOCK(NetEventsInterface::g_msgproc_mutex);

    ChainstateManager& chainman{*Assert(m_node.chainman)};
    PeerManager& peerman{*Assert(m_node.peerman)};
    ConnmanTestMsg& connman{static_cast<ConnmanTestMsg&>(*m_node.connman)};

    const CBlockIndex* start_tip{
        WITH_LOCK(::cs_main, return chainman.ActiveChain().Tip())};
    BOOST_REQUIRE(start_tip != nullptr);
    mineBlock(m_node, std::chrono::seconds{start_tip->GetBlockTime() + 1});
    mineBlock(m_node,
              std::chrono::seconds{
                  WITH_LOCK(::cs_main, return chainman.ActiveTip()->GetBlockTime()) +
                  1});

    node::matmul_trusted::ResetForTest();
    CKey signer;
    signer.MakeNewKey(/*fCompressed=*/true);
    matmul::trusted::StoreConfig config;
    config.chain_id = uint256::FromHex(std::string(64, '1')).value();
    config.replay_authority_context =
        uint256::FromHex(std::string(64, '2')).value();
    config.trusted_signers = {signer.GetPubKey()};
    config.threshold = 1;
    std::string error;
    BOOST_REQUIRE(node::matmul_trusted::Configure(
        std::move(config), /*trusted_mirror=*/true, /*serve=*/false,
        std::chrono::milliseconds{50}, error));
    BOOST_REQUIRE(node::matmul_trusted::IsTrustedMirror());
    struct MirrorReset {
        ~MirrorReset() { node::matmul_trusted::ResetForTest(); }
    } mirror_reset;

    const CBlockIndex* tip{
        WITH_LOCK(::cs_main, return chainman.ActiveChain().Tip())};
    BOOST_REQUIRE(tip != nullptr);
    BOOST_REQUIRE(tip->nHeight >= 2);
    SetMockTime(std::chrono::seconds{tip->GetBlockTime() + 1});

    Consensus::Params& consensus = const_cast<Consensus::Params&>(
        chainman.GetParams().GetConsensus());
    auto& mode = const_cast<kernel::MatMulValidationMode&>(
        chainman.m_options.matmul_validation_mode);
    const int32_t saved_rc = consensus.nMatMulRCHeight;
    const int32_t saved_v4 = consensus.nMatMulV4Height;
    const int32_t saved_bmx4c = consensus.nMatMulBMX4CHeight;
    const int32_t saved_drlt = consensus.nMatMulDRLTHeight;
    const int32_t saved_coupled = consensus.nMatMulRCCoupledHeight;
    const auto saved_mode{mode};
    struct RestoreHeights {
        Consensus::Params& params;
        kernel::MatMulValidationMode& mode;
        int32_t rc;
        int32_t v4;
        int32_t bmx4c;
        int32_t drlt;
        int32_t coupled;
        kernel::MatMulValidationMode saved_mode;
        ~RestoreHeights()
        {
            params.nMatMulRCHeight = rc;
            params.nMatMulV4Height = v4;
            params.nMatMulBMX4CHeight = bmx4c;
            params.nMatMulDRLTHeight = drlt;
            params.nMatMulRCCoupledHeight = coupled;
            mode = saved_mode;
        }
    } restore_heights{consensus, mode, saved_rc, saved_v4, saved_bmx4c,
                      saved_drlt, saved_coupled, saved_mode};

    const int32_t activation{tip->nHeight + 1};
    consensus.nMatMulV4Height = activation;
    consensus.nMatMulBMX4CHeight = activation;
    consensus.nMatMulDRLTHeight = std::numeric_limits<int32_t>::max();
    consensus.nMatMulRCHeight = activation;
    consensus.nMatMulRCCoupledHeight = std::numeric_limits<int32_t>::max();
    mode = kernel::MatMulValidationMode::TRUSTED;
    peerman.SetBestBlock(tip->nHeight, std::chrono::seconds{tip->GetBlockTime()});
    BOOST_REQUIRE(consensus.IsMatMulTrustedReplayAttestationActive(activation));

    {
        LOCK(::cs_main);
        BOOST_CHECK(chainman.IsMatMulFollowedHistoricalHole(
            tip->pprev != nullptr ? tip->pprev : nullptr) ==
                    (tip->pprev != nullptr));
        BOOST_CHECK(!chainman.IsMatMulFollowedHistoricalHole(tip));
        BOOST_CHECK(!chainman.IsMatMulFollowedHistoricalHole(nullptr));
        if (tip->pprev != nullptr) {
            CBlock ancestor_block;
            BOOST_REQUIRE(chainman.m_blockman.ReadBlock(ancestor_block, *tip->pprev));
            BlockValidationState state;
            bool new_block{false};
            CBlockIndex* pindex{nullptr};
            BOOST_REQUIRE(chainman.AcceptBlock(
                std::make_shared<const CBlock>(ancestor_block), state, &pindex,
                /*fRequested=*/false, nullptr, &new_block,
                /*min_pow_checked=*/true));
            BOOST_REQUIRE(pindex != nullptr);
            BOOST_CHECK(pindex->nStatus & BLOCK_HAVE_DATA);
            BOOST_CHECK(chainman.IsMatMulFollowedHistoricalHole(pindex));
        }
    }

    CBlock child = node::BlockAssembler{
        chainman.ActiveChainstate(), nullptr, {}, m_node}
                       .CreateNewBlock()
                       ->block;
    child.hashMerkleRoot = BlockMerkleRoot(child);
    BOOST_REQUIRE(MineHeaderForConsensus(
        child, activation, chainman.GetConsensus(), 5'000'000,
        tip->GetMedianTimePast()));
    const uint256 child_hash{child.GetHash()};
    BOOST_CHECK(!node::matmul_trusted::HasQuorum(child_hash, activation));

    const ServiceFlags services{ServiceFlags(NODE_NETWORK | NODE_WITNESS)};
    CNode peer{/*id=*/97, /*sock=*/nullptr, CAddress{},
               /*nKeyedNetGroupIn=*/0, /*nLocalHostNonceIn=*/0,
               CAddress{}, /*addrNameIn=*/"unreq-followed-tip-child",
               ConnectionType::INBOUND,
               /*inbound_onion=*/false, /*network_key=*/0};
    connman.Handshake(peer, /*successfully_connected=*/true, services,
                      services, PROTOCOL_VERSION, /*relay_txs=*/true);
    connman.AddTestNode(peer);
    connman.FlushSendBuffer(peer);
    struct FinalizePeer {
        PeerManager& peerman;
        ConnmanTestMsg& connman;
        CNode& peer;
        ~FinalizePeer()
        {
            peerman.FinalizeNode(peer);
            connman.RemoveTestNode(peer);
        }
    } finalize{peerman, connman, peer};

    if (tip->pprev != nullptr) {
        CBlock ancestor_block;
        const uint256 ancestor_hash{tip->pprev->GetBlockHash()};
        BOOST_REQUIRE(WITH_LOCK(
            ::cs_main,
            return chainman.m_blockman.ReadBlock(ancestor_block, *tip->pprev)));
        BOOST_REQUIRE(connman.ReceiveMsgFrom(
            peer, NetMsg::Make(NetMsgType::BLOCK, TX_WITH_WITNESS(ancestor_block))));
        peer.fPauseSend = false;
        (void)connman.ProcessMessagesOnce(peer);
        m_node.validation_signals->SyncWithValidationInterfaceQueue();
        {
            LOCK(::cs_main);
            const CBlockIndex* idx{
                chainman.m_blockman.LookupBlockIndex(ancestor_hash)};
            BOOST_REQUIRE(idx != nullptr);
            BOOST_CHECK(idx->nStatus & BLOCK_HAVE_DATA);
            BOOST_CHECK(chainman.IsMatMulFollowedHistoricalHole(idx));
        }
    }

    BOOST_REQUIRE(connman.ReceiveMsgFrom(
        peer, NetMsg::Make(NetMsgType::BLOCK, TX_WITH_WITNESS(child))));
    peer.fPauseSend = false;
    (void)connman.ProcessMessagesOnce(peer);
    m_node.validation_signals->SyncWithValidationInterfaceQueue();

    {
        LOCK(::cs_main);
        const CBlockIndex* idx{chainman.m_blockman.LookupBlockIndex(child_hash)};
        BOOST_REQUIRE(idx != nullptr);
        BOOST_CHECK(idx->nStatus & BLOCK_HAVE_DATA);
        BOOST_CHECK_EQUAL(idx->pprev, tip);
        BOOST_CHECK(!chainman.ActiveChain().Contains(idx));
        BOOST_CHECK(!chainman.IsMatMulFollowedHistoricalHole(idx));
    }

    // Unrequested less-work competing fork must stay HEADER_ONLY.
    BOOST_REQUIRE(tip->nHeight >= 1);
    auto competing = CreateBlockChain(1, chainman.GetParams());
    BOOST_REQUIRE_EQUAL(competing.size(), 1U);
    const uint256 competing_hash{competing[0]->GetHash()};
    BOOST_REQUIRE(connman.ReceiveMsgFrom(
        peer, NetMsg::Make(NetMsgType::BLOCK, TX_WITH_WITNESS(*competing[0]))));
    peer.fPauseSend = false;
    (void)connman.ProcessMessagesOnce(peer);
    m_node.validation_signals->SyncWithValidationInterfaceQueue();
    {
        LOCK(::cs_main);
        const CBlockIndex* idx{
            chainman.m_blockman.LookupBlockIndex(competing_hash)};
        if (idx != nullptr) {
            BOOST_CHECK(!(idx->nStatus & BLOCK_HAVE_DATA));
            BOOST_CHECK(!chainman.IsMatMulFollowedHistoricalHole(idx));
            BlockValidationState st;
            bool reaches{false};
            const bool cheap{chainman.CheckMatMulBlockAdmissionPreconditions(
                *competing[0], st, /*force_processing=*/false,
                /*min_pow_checked=*/true, reaches)};
            if (cheap) {
                BOOST_CHECK(!reaches);
            }
        }
    }
    {
        LOCK(::cs_main);
        chainman.SetBestHeader(const_cast<CBlockIndex*>(chainman.ActiveTip()));
        CBlockIndex* persisted{
            chainman.m_blockman.LookupBlockIndex(child_hash)};
        if (persisted != nullptr) {
            persisted->nStatus &= ~BLOCK_HAVE_DATA;
            persisted->nTx = 0;
            persisted->m_chain_tx_count = 0;
            chainman.ActiveChainstate().setBlockIndexCandidates.erase(persisted);
        }
    }
}

BOOST_AUTO_TEST_CASE(ticketless_followed_chain_body_is_persisted_or_retained)
{
    // Unsolicited ticketless followed-chain body must not be HEADER_ONLY
    // discarded then re-getdata'd forever. Persist HAVE_DATA or retain the
    // only copy; bound getdata per hash well below the 150–301 livelock.
    LOCK(NetEventsInterface::g_msgproc_mutex);

    ConnmanTestMsg& connman{static_cast<ConnmanTestMsg&>(*m_node.connman)};
    PeerManager& peerman{*Assert(m_node.peerman)};
    const ServiceFlags services{ServiceFlags(NODE_NETWORK | NODE_WITNESS)};
    CNode source{/*id=*/101, /*sock=*/nullptr, CAddress{},
                 /*nKeyedNetGroupIn=*/11, /*nLocalHostNonceIn=*/0,
                 CAddress{}, /*addrNameIn=*/"ticketless-followed",
                 ConnectionType::OUTBOUND_FULL_RELAY,
                 /*inbound_onion=*/false, /*network_key=*/0};
    connman.Handshake(source, /*successfully_connected=*/true, services,
                      services, PROTOCOL_VERSION, /*relay_txs=*/true);
    connman.AddTestNode(source);
    connman.FlushSendBuffer(source);
    struct FinalizePeer {
        ConnmanTestMsg& connman;
        PeerManager& peerman;
        CNode& node;
        ~FinalizePeer()
        {
            peerman.FinalizeNode(node);
            connman.RemoveTestNode(node);
        }
    } finalize{connman, peerman, source};

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
    const int32_t saved_coupled = consensus.nMatMulRCCoupledHeight;
    struct RestoreHeights {
        Consensus::Params& params;
        int32_t rc;
        int32_t v4;
        int32_t bmx4c;
        int32_t drlt;
        int32_t coupled;
        ~RestoreHeights()
        {
            params.nMatMulRCHeight = rc;
            params.nMatMulV4Height = v4;
            params.nMatMulBMX4CHeight = bmx4c;
            params.nMatMulDRLTHeight = drlt;
            params.nMatMulRCCoupledHeight = coupled;
        }
    } restore_heights{consensus, saved_rc, saved_v4, saved_bmx4c, saved_drlt,
                      saved_coupled};

    const int32_t activation{tip->nHeight + 1};
    consensus.nMatMulV4Height = activation;
    consensus.nMatMulBMX4CHeight = activation;
    consensus.nMatMulDRLTHeight = std::numeric_limits<int32_t>::max();
    consensus.nMatMulRCHeight = activation;
    consensus.nMatMulRCCoupledHeight = std::numeric_limits<int32_t>::max();
    peerman.SetBestBlock(tip->nHeight, std::chrono::seconds{tip->GetBlockTime()});

    CBlock followed = node::BlockAssembler{
        m_node.chainman->ActiveChainstate(), nullptr, {}, m_node}
                          .CreateNewBlock()
                          ->block;
    followed.hashMerkleRoot = BlockMerkleRoot(followed);
    BOOST_REQUIRE(MineHeaderForConsensus(
        followed, activation, m_node.chainman->GetConsensus(), 5'000'000,
        tip->GetMedianTimePast()));
    const uint256 followed_hash{followed.GetHash()};

    // Index the header without P2P DirectFetch so the body stays unsolicited
    // (no ticket_exempt ExactReplay). That is the ticketless livelock: body
    // delivered, HEADER_ONLY-dropped, re-getdata forever.
    {
        BlockValidationState hdr_state;
        BOOST_REQUIRE(m_node.chainman->ProcessNewBlockHeaders(
            {{followed.GetBlockHeader()}}, /*min_pow_checked=*/true, hdr_state));
    }

    BOOST_REQUIRE(connman.ReceiveMsgFrom(
        source, NetMsg::Make(NetMsgType::BLOCK, TX_WITH_WITNESS(followed))));
    source.fPauseSend = false;
    (void)connman.ProcessMessagesOnce(source);

    const bool have_data{WITH_LOCK(::cs_main, {
        const CBlockIndex* index{
            m_node.chainman->m_blockman.LookupBlockIndex(followed_hash)};
        return index != nullptr && (index->nStatus & BLOCK_HAVE_DATA) != 0;
    })};
    const bool retained{peerman.UnitTestHasMatMulRetainedBody(followed_hash)};
    BOOST_CHECK_MESSAGE(have_data || retained,
                        "ticketless followed-chain body must be persisted or "
                        "retained, not HEADER_ONLY-discarded");

    int requests{0};
    for (int i = 0; i < 25; ++i) {
        BOOST_CHECK(peerman.SendMessages(&source));
        requests += CountQueuedGetDataForHash(source, followed_hash);
        connman.FlushSendBuffer(source);
    }
    BOOST_CHECK_LT(requests, 20);

    CBlockIndex* followed_connected{WITH_LOCK(::cs_main, {
        CBlockIndex* idx{m_node.chainman->m_blockman.LookupBlockIndex(
            followed_hash)};
        return (idx != nullptr && m_node.chainman->ActiveChain().Contains(idx))
                   ? idx
                   : nullptr;
    })};
    if (followed_connected != nullptr) {
        BlockValidationState invalidate_state;
        (void)m_node.chainman->ActiveChainstate().InvalidateBlock(
            invalidate_state, followed_connected);
    }
    {
        LOCK(::cs_main);
        m_node.chainman->SetBestHeader(
            const_cast<CBlockIndex*>(m_node.chainman->ActiveTip()));
    }
}

BOOST_AUTO_TEST_CASE(ticketless_competing_sibling_does_not_censor_independent_netgroup)
{
    // One ticketless competing sibling must not suppress getdata from an
    // independent netgroup, and must not persist HAVE_DATA (miner GPU /
    // HEADER_ONLY competing policy).
    LOCK(NetEventsInterface::g_msgproc_mutex);

    ConnmanTestMsg& connman{static_cast<ConnmanTestMsg&>(*m_node.connman)};
    PeerManager& peerman{*Assert(m_node.peerman)};
    ChainstateManager& chainman{*Assert(m_node.chainman)};
    const ServiceFlags services{ServiceFlags(NODE_NETWORK | NODE_WITNESS)};

    CNode attacker{/*id=*/102, /*sock=*/nullptr, CAddress{},
                   /*nKeyedNetGroupIn=*/11, /*nLocalHostNonceIn=*/0,
                   CAddress{}, /*addrNameIn=*/"ticketless-competing-a",
                   ConnectionType::OUTBOUND_FULL_RELAY,
                   /*inbound_onion=*/false, /*network_key=*/0};
    CNode honest{/*id=*/103, /*sock=*/nullptr, CAddress{},
                 /*nKeyedNetGroupIn=*/22, /*nLocalHostNonceIn=*/0,
                 CAddress{}, /*addrNameIn=*/"ticketless-competing-b",
                 ConnectionType::OUTBOUND_FULL_RELAY,
                 /*inbound_onion=*/false, /*network_key=*/0};
    connman.Handshake(attacker, /*successfully_connected=*/true, services,
                      services, PROTOCOL_VERSION, /*relay_txs=*/true);
    connman.Handshake(honest, /*successfully_connected=*/true, services,
                      services, PROTOCOL_VERSION, /*relay_txs=*/true);
    connman.AddTestNode(attacker);
    connman.AddTestNode(honest);
    connman.FlushSendBuffer(attacker);
    connman.FlushSendBuffer(honest);
    struct FinalizePeers {
        PeerManager& peerman;
        ConnmanTestMsg& connman;
        CNode& attacker;
        CNode& honest;
        ~FinalizePeers()
        {
            peerman.FinalizeNode(attacker);
            peerman.FinalizeNode(honest);
            connman.RemoveTestNode(attacker);
            connman.RemoveTestNode(honest);
        }
    } finalize{peerman, connman, attacker, honest};

    const CBlockIndex* starting_tip{
        WITH_LOCK(::cs_main, return chainman.ActiveChain().Tip())};
    BOOST_REQUIRE(starting_tip != nullptr);
    SetMockTime(std::chrono::seconds{starting_tip->GetBlockTime() + 3600});

    // Real coinbase body parented at starting_tip, then mine a different
    // child as the winner. The first body becomes a same-height sibling of
    // the active tip (not a tip-child).
    CBlock sibling = node::BlockAssembler{
        chainman.ActiveChainstate(), nullptr, {}, m_node}
                         .CreateNewBlock()
                         ->block;
    sibling.hashMerkleRoot = BlockMerkleRoot(sibling);
    BOOST_REQUIRE(MineHeaderForConsensus(
        sibling, starting_tip->nHeight + 1, chainman.GetConsensus(), 5'000'000,
        starting_tip->GetMedianTimePast()));

    mineBlock(m_node, std::chrono::seconds{starting_tip->GetBlockTime() + 3600});
    const CBlockIndex* tip{
        WITH_LOCK(::cs_main, return chainman.ActiveChain().Tip())};
    BOOST_REQUIRE(tip != nullptr);
    BOOST_REQUIRE(tip->pprev != nullptr);
    BOOST_REQUIRE(sibling.hashPrevBlock == tip->pprev->GetBlockHash());
    BOOST_REQUIRE(sibling.GetHash() != tip->GetBlockHash());

    const CBlockHeader sibling_header{sibling.GetBlockHeader()};
    const uint256 sibling_hash{sibling.GetHash()};

    Consensus::Params& consensus = const_cast<Consensus::Params&>(
        chainman.GetParams().GetConsensus());
    const int32_t saved_rc = consensus.nMatMulRCHeight;
    const int32_t saved_v4 = consensus.nMatMulV4Height;
    const int32_t saved_bmx4c = consensus.nMatMulBMX4CHeight;
    const int32_t saved_drlt = consensus.nMatMulDRLTHeight;
    const int32_t saved_coupled = consensus.nMatMulRCCoupledHeight;
    struct RestoreHeights {
        Consensus::Params& params;
        int32_t rc;
        int32_t v4;
        int32_t bmx4c;
        int32_t drlt;
        int32_t coupled;
        ~RestoreHeights()
        {
            params.nMatMulRCHeight = rc;
            params.nMatMulV4Height = v4;
            params.nMatMulBMX4CHeight = bmx4c;
            params.nMatMulDRLTHeight = drlt;
            params.nMatMulRCCoupledHeight = coupled;
        }
    } restore_heights{consensus, saved_rc, saved_v4, saved_bmx4c, saved_drlt,
                      saved_coupled};

    // Activate RC at the current tip height AFTER the pre-RC winner and
    // sibling header are indexed, so local mining did not run ExactReplay.
    // The ticketless competing body at this height then takes HEADER_ONLY
    // rather than HAVE_DATA / retain.
    const int32_t activation{tip->nHeight};
    consensus.nMatMulV4Height = activation;
    consensus.nMatMulBMX4CHeight = activation;
    consensus.nMatMulDRLTHeight = std::numeric_limits<int32_t>::max();
    consensus.nMatMulRCHeight = activation;
    consensus.nMatMulRCCoupledHeight = std::numeric_limits<int32_t>::max();
    peerman.SetBestBlock(tip->nHeight, std::chrono::seconds{tip->GetBlockTime()});

    // Competing sibling of the active tip: same parent, not the tip itself,
    // not a tip-child. HEADER_ONLY / no retain; independent netgroup 22
    // must still be able to getdata.
    std::vector<CBlock> headers{CBlock{sibling_header}};
    BOOST_REQUIRE(connman.ReceiveMsgFrom(
        attacker,
        NetMsg::Make(NetMsgType::HEADERS, TX_WITH_WITNESS(headers))));
    attacker.fPauseSend = false;
    (void)connman.ProcessMessagesOnce(attacker);
    connman.FlushSendBuffer(attacker);

    BOOST_REQUIRE(connman.ReceiveMsgFrom(
        attacker, NetMsg::Make(NetMsgType::BLOCK, TX_WITH_WITNESS(sibling))));
    (void)connman.ProcessMessagesOnce(attacker);

    const bool have_data{WITH_LOCK(::cs_main, {
        const CBlockIndex* index{
            chainman.m_blockman.LookupBlockIndex(sibling_hash)};
        return index != nullptr && (index->nStatus & BLOCK_HAVE_DATA) != 0;
    })};
    BOOST_CHECK(!have_data);
    BOOST_CHECK(!peerman.UnitTestHasMatMulRetainedBody(sibling_hash));

    BOOST_REQUIRE(connman.ReceiveMsgFrom(
        honest, NetMsg::Make(NetMsgType::HEADERS, TX_WITH_WITNESS(headers))));
    honest.fPauseSend = false;
    (void)connman.ProcessMessagesOnce(honest);
    connman.FlushSendBuffer(honest);
    for (int i = 0; i < 5; ++i) {
        BOOST_CHECK(peerman.SendMessages(&honest));
        BOOST_CHECK(!honest.fDisconnect);
        connman.FlushSendBuffer(honest);
    }
    // Equal-work losing siblings are not required to be fetched; the
    // invariant is that HEADER_ONLY + per-netgroup cooldown must not
    // disconnect or globally skip an independent source.
    BOOST_CHECK(!honest.fDisconnect);
    BOOST_CHECK(!attacker.fDisconnect);
}

namespace {
CService PeermanTestService(uint32_t ipv4)
{
    struct in_addr s{};
    s.s_addr = ipv4;
    return CService(CNetAddr(s), Params().GetDefaultPort());
}

template <typename Pred>
bool PeermanWaitFor(Pred pred, std::chrono::milliseconds timeout = std::chrono::milliseconds{20000})
{
    const auto deadline{std::chrono::steady_clock::now() + timeout};
    while (!pred()) {
        if (std::chrono::steady_clock::now() > deadline) return pred();
        std::this_thread::sleep_for(std::chrono::milliseconds{2});
    }
    return true;
}

struct PeermanBlockingVerify {
    std::mutex mutex;
    std::condition_variable cv;
    bool released{false};
    std::atomic<int> running{0};

    bool Run()
    {
        ++running;
        std::unique_lock<std::mutex> lock(mutex);
        cv.wait(lock, [this] { return released; });
        --running;
        return true;
    }
    void Release()
    {
        {
            std::lock_guard<std::mutex> lock(mutex);
            released = true;
        }
        cv.notify_all();
    }
    ~PeermanBlockingVerify() { Release(); }
};

struct RestoreMatMulHeights {
    Consensus::Params& params;
    int32_t rc;
    int32_t v4;
    int32_t bmx4c;
    int32_t drlt;
    int32_t coupled;
    uint32_t peer_budget;
    uint32_t global_budget;
    uint32_t max_pending;
    ~RestoreMatMulHeights()
    {
        params.nMatMulRCHeight = rc;
        params.nMatMulV4Height = v4;
        params.nMatMulBMX4CHeight = bmx4c;
        params.nMatMulDRLTHeight = drlt;
        params.nMatMulRCCoupledHeight = coupled;
        params.nMatMulRCPeerVerifyBudgetPerMin = peer_budget;
        params.nMatMulRCGlobalVerifyBudgetPerMin = global_budget;
        params.nMatMulRCMaxPendingVerifications = max_pending;
    }
};

RestoreMatMulHeights SaveMatMulHeights(Consensus::Params& consensus)
{
    return RestoreMatMulHeights{
        consensus,
        consensus.nMatMulRCHeight,
        consensus.nMatMulV4Height,
        consensus.nMatMulBMX4CHeight,
        consensus.nMatMulDRLTHeight,
        consensus.nMatMulRCCoupledHeight,
        consensus.nMatMulRCPeerVerifyBudgetPerMin,
        consensus.nMatMulRCGlobalVerifyBudgetPerMin,
        consensus.nMatMulRCMaxPendingVerifications,
    };
}

void ActivateRcAtTip(Consensus::Params& consensus, const CBlockIndex& tip)
{
    consensus.nMatMulV4Height = tip.nHeight;
    consensus.nMatMulBMX4CHeight = tip.nHeight;
    consensus.nMatMulDRLTHeight = std::numeric_limits<int32_t>::max();
    consensus.nMatMulRCHeight = tip.nHeight;
    consensus.nMatMulRCCoupledHeight = std::numeric_limits<int32_t>::max();
}

CBlock MineTipChild(const node::NodeContext& node, const CBlockIndex& tip, int64_t extra_time)
{
    CBlock block = node::BlockAssembler{
        node.chainman->ActiveChainstate(), nullptr, {}, node}
                       .CreateNewBlock()
                       ->block;
    block.nTime = static_cast<uint32_t>(tip.GetBlockTime() + 1 + extra_time);
    block.hashMerkleRoot = BlockMerkleRoot(block);
    BOOST_REQUIRE(MineHeaderForConsensus(
        block, tip.nHeight + 1, node.chainman->GetConsensus(), 5'000'000,
        tip.GetMedianTimePast()));
    return block;
}

node::RCAdmissionTicket GrindTicket(const CBlockHeader& header, const uint256& pow_limit)
{
    node::RCAdmissionTicket ticket{header.GetHash(), 0};
    uint64_t tries{2'000'000};
    BOOST_REQUIRE(node::GrindRCAdmissionTicket(header, pow_limit, ticket, tries));
    return ticket;
}
} // namespace

BOOST_AUTO_TEST_CASE(handoff_peer_budget_miss_retains_tip_child_body)
{
    LOCK(NetEventsInterface::g_msgproc_mutex);

    node::matmul_trusted::ResetForTest();
    ResetSharedPeermanFixture(m_node);
    ConnmanTestMsg& connman = static_cast<ConnmanTestMsg&>(*m_node.connman);
    PeerManager& peerman = *m_node.peerman;
    ResetGlobalMatMulRCBudgetForTest();

    const CBlockIndex* tip{
        WITH_LOCK(::cs_main, return m_node.chainman->ActiveChain().Tip())};
    BOOST_REQUIRE(tip != nullptr);
    SetMockTime(std::chrono::seconds{tip->GetBlockTime() + 1});
    peerman.SetBestBlock(tip->nHeight, std::chrono::seconds{tip->GetBlockTime()});

    Consensus::Params& consensus = const_cast<Consensus::Params&>(
        m_node.chainman->GetParams().GetConsensus());
    auto restore_heights{SaveMatMulHeights(consensus)};
    ActivateRcAtTip(consensus, *tip);
    consensus.nMatMulRCPeerVerifyBudgetPerMin =
        MatMulRCWorkUnits(consensus, tip->nHeight + 1);

    PeermanBlockingVerify gate;
    peerman.InstallMatMulVerifyOverrideForTest(
        [&](const CBlock&, int32_t, std::optional<int64_t>) { return gate.Run(); });
    struct ClearHandoffOverride {
        PeerManager& peerman;
        ~ClearHandoffOverride() { peerman.InstallMatMulVerifyOverrideForTest({}); }
    } clear_handoff_override{peerman};

    const ServiceFlags services{ServiceFlags(NODE_NETWORK | NODE_WITNESS | NODE_MATMUL_CONSENSUS)};
    CNode peer{/*id=*/201,
               /*sock=*/nullptr,
               CAddress{PeermanTestService(0x0100007f), NODE_NETWORK},
               /*nKeyedNetGroupIn=*/0x11,
               /*nLocalHostNonceIn=*/0,
               CAddress{},
               /*addrNameIn=*/"handoff-budget-peer",
               ConnectionType::OUTBOUND_FULL_RELAY,
               /*inbound_onion=*/false,
               /*network_key=*/0};
    connman.Handshake(peer, /*successfully_connected=*/true, services, services,
                      PROTOCOL_VERSION, /*relay_txs=*/true);
    connman.AddTestNode(peer);
    connman.FlushSendBuffer(peer);
    struct FinalizePeer {
        ConnmanTestMsg& connman;
        PeerManager& peerman;
        CNode& node;
        ~FinalizePeer()
        {
            peerman.FinalizeNode(node);
            connman.RemoveTestNode(node);
        }
    } finalize{connman, peerman, peer};

    CBlock competing{MineTipChild(m_node, *tip, /*extra_time=*/0)};
    CBlock honest{MineTipChild(m_node, *tip, /*extra_time=*/1)};
    BOOST_REQUIRE(competing.GetHash() != honest.GetHash());
    const uint256 honest_hash{honest.GetHash()};
    const auto competing_ticket{
        GrindTicket(competing.GetBlockHeader(), consensus.powLimit)};
    const auto honest_ticket{
        GrindTicket(honest.GetBlockHeader(), consensus.powLimit)};

    std::vector<CBlock> competing_headers{CBlock{competing.GetBlockHeader()}};
    BOOST_REQUIRE(connman.ReceiveMsgFrom(
        peer, NetMsg::Make(NetMsgType::HEADERS, TX_WITH_WITNESS(competing_headers))));
    peer.fPauseSend = false;
    (void)connman.ProcessMessagesOnce(peer);
    BOOST_REQUIRE_MESSAGE(
        WITH_LOCK(::cs_main,
                  return m_node.chainman->m_blockman.LookupBlockIndex(
                             competing.GetHash()) != nullptr),
        "competing header was not indexed after HEADERS");
    BOOST_REQUIRE(!m_node.chainman->IsInitialBlockDownload());
    connman.FlushSendBuffer(peer);
    BOOST_REQUIRE(connman.ReceiveMsgFrom(
        peer, NetMsg::Make(NetMsgType::RCADMIT, competing_ticket)));
    peer.fPauseSend = false;
    (void)connman.ProcessMessagesOnce(peer);
    BOOST_REQUIRE(PeermanWaitFor([&] { return gate.running.load() >= 1; }));

    std::vector<CBlock> honest_headers{CBlock{honest.GetBlockHeader()}};
    connman.FlushSendBuffer(peer);
    BOOST_REQUIRE(connman.ReceiveMsgFrom(
        peer, NetMsg::Make(NetMsgType::HEADERS, TX_WITH_WITNESS(honest_headers))));
    peer.fPauseSend = false;
    (void)connman.ProcessMessagesOnce(peer);
    // Header-first handoff miss must keep the download source: the body is
    // still in-flight and AdmitMatMulBlockVerification retains it.
    BOOST_CHECK(!peer.fDisconnect);
    connman.FlushSendBuffer(peer);
    BOOST_REQUIRE(connman.ReceiveMsgFrom(
        peer, NetMsg::Make(NetMsgType::RCADMIT, honest_ticket)));
    peer.fPauseSend = false;
    (void)connman.ProcessMessagesOnce(peer);
    connman.FlushSendBuffer(peer);
    BOOST_REQUIRE(connman.ReceiveMsgFrom(
        peer, NetMsg::Make(NetMsgType::BLOCK, TX_WITH_WITNESS(honest))));
    peer.fPauseSend = false;
    (void)connman.ProcessMessagesOnce(peer);

    BOOST_CHECK(!peer.fDisconnect);
    BOOST_CHECK(peerman.HasMatMulRetainedBodyForTest(honest_hash));
    {
        LOCK(::cs_main);
        const CBlockIndex* idx{
            m_node.chainman->m_blockman.LookupBlockIndex(honest_hash)};
        BOOST_REQUIRE(idx != nullptr);
        BOOST_CHECK_EQUAL(idx->nStatus & BLOCK_HAVE_DATA, 0);
    }

    size_t requests{0};
    for (int i = 0; i < 25; ++i) {
        connman.FlushSendBuffer(peer);
        BOOST_CHECK(peerman.SendMessages(&peer));
        requests += CountQueuedGetDataForHash(peer, honest_hash);
        BOOST_CHECK(!peer.fDisconnect);
    }
    BOOST_CHECK_LT(requests, 20U);
    NeutralizeUnconnectedHeaders(*Assert(m_node.chainman));
    peerman.ResetMatMulVerifyAdmissionForTest();
}

BOOST_AUTO_TEST_CASE(competing_sibling_stays_header_only_on_trusted_mirror)
{
    LOCK(NetEventsInterface::g_msgproc_mutex);

    node::matmul_trusted::ResetForTest();
    ResetSharedPeermanFixture(m_node);
    CKey signer;
    signer.MakeNewKey(/*fCompressed=*/true);
    matmul::trusted::StoreConfig config;
    config.chain_id = uint256::FromHex(std::string(64, '1')).value();
    config.replay_authority_context =
        uint256::FromHex(std::string(64, '2')).value();
    config.trusted_signers = {signer.GetPubKey()};
    config.threshold = 1;
    std::string error;
    BOOST_REQUIRE(node::matmul_trusted::Configure(
        std::move(config), /*trusted_mirror=*/true, /*serve=*/false,
        std::chrono::milliseconds{50}, error));
    BOOST_REQUIRE(node::matmul_trusted::IsTrustedMirror());
    struct MirrorReset {
        ~MirrorReset() { node::matmul_trusted::ResetForTest(); }
    } mirror_reset;

    ConnmanTestMsg& connman = static_cast<ConnmanTestMsg&>(*m_node.connman);
    PeerManager& peerman = *m_node.peerman;

    const CBlockIndex* tip{
        WITH_LOCK(::cs_main, return m_node.chainman->ActiveChain().Tip())};
    BOOST_REQUIRE(tip != nullptr);
    SetMockTime(std::chrono::seconds{tip->GetBlockTime() + 1});
    peerman.SetBestBlock(tip->nHeight, std::chrono::seconds{tip->GetBlockTime()});

    Consensus::Params& consensus = const_cast<Consensus::Params&>(
        m_node.chainman->GetParams().GetConsensus());
    auto restore_heights{SaveMatMulHeights(consensus)};
    ActivateRcAtTip(consensus, *tip);

    const ServiceFlags services{ServiceFlags(
        NODE_NETWORK | NODE_WITNESS | NODE_MATMUL_CONSENSUS |
        NODE_MATMUL_ATTESTATION_ARCHIVE)};
    CNode peer{/*id=*/202,
               /*sock=*/nullptr,
               CAddress{PeermanTestService(0x0200007f), NODE_NETWORK},
               /*nKeyedNetGroupIn=*/0x22,
               /*nLocalHostNonceIn=*/0,
               CAddress{},
               /*addrNameIn=*/"competing-sibling-mirror",
               ConnectionType::OUTBOUND_FULL_RELAY,
               /*inbound_onion=*/false,
               /*network_key=*/0};
    connman.Handshake(peer, /*successfully_connected=*/true, services, services,
                      PROTOCOL_VERSION, /*relay_txs=*/true);
    connman.AddTestNode(peer);
    connman.FlushSendBuffer(peer);
    struct FinalizePeer {
        ConnmanTestMsg& connman;
        PeerManager& peerman;
        CNode& node;
        ~FinalizePeer()
        {
            peerman.FinalizeNode(node);
            connman.RemoveTestNode(node);
        }
    } finalize{connman, peerman, peer};

    CBlock followed{MineTipChild(m_node, *tip, /*extra_time=*/0)};
    CBlock competing{MineTipChild(m_node, *tip, /*extra_time=*/1)};
    BOOST_REQUIRE(followed.GetHash() != competing.GetHash());
    const uint256 competing_hash{competing.GetHash()};

    auto send_block = [&](const CBlock& block) {
        std::vector<CBlock> headers{CBlock{block.GetBlockHeader()}};
        BOOST_REQUIRE(connman.ReceiveMsgFrom(
            peer, NetMsg::Make(NetMsgType::HEADERS, TX_WITH_WITNESS(headers))));
        peer.fPauseSend = false;
        (void)connman.ProcessMessagesOnce(peer);
        connman.FlushSendBuffer(peer);
        BOOST_REQUIRE(connman.ReceiveMsgFrom(
            peer, NetMsg::Make(NetMsgType::BLOCK, TX_WITH_WITNESS(block))));
        peer.fPauseSend = false;
        (void)connman.ProcessMessagesOnce(peer);
    };
    send_block(followed);
    send_block(competing);

    BOOST_CHECK(!peer.fDisconnect);
    BOOST_CHECK(!peerman.HasMatMulRetainedBodyForTest(competing_hash));
    {
        LOCK(::cs_main);
        const CBlockIndex* idx{
            m_node.chainman->m_blockman.LookupBlockIndex(competing_hash)};
        BOOST_REQUIRE(idx != nullptr);
        BOOST_CHECK_EQUAL(idx->nStatus & BLOCK_HAVE_DATA, 0);
    }

    size_t requests{0};
    for (int i = 0; i < 25; ++i) {
        connman.FlushSendBuffer(peer);
        BOOST_CHECK(peerman.SendMessages(&peer));
        requests += CountQueuedGetDataForHash(peer, competing_hash);
        BOOST_CHECK(!peer.fDisconnect);
    }
    BOOST_CHECK_LT(requests, 20U);

    // Late MMATTEST quorum must unsuppress HEADER_ONLY so FindNextBlocks
    // issues getdata for the now-authenticated sibling. Tip-move clears
    // used to be the only escape, and this sibling never moved the tip.
    matmul::trusted::ExactReplayStatement statement;
    statement.chain_id = uint256::FromHex(std::string(64, '1')).value();
    statement.block_hash = competing_hash;
    statement.block_height = tip->nHeight + 1;
    statement.replay_authority_context =
        uint256::FromHex(std::string(64, '2')).value();
    auto attestation{matmul::trusted::SignStatement(statement, signer)};
    BOOST_REQUIRE(attestation.has_value());
    std::vector<matmul::trusted::ExactReplayAttestation> mmattest{
        *attestation};
    BOOST_REQUIRE(connman.ReceiveMsgFrom(
        peer, NetMsg::Make(NetMsgType::MMATTEST, mmattest)));
    peer.fPauseSend = false;
    (void)connman.ProcessMessagesOnce(peer);
    BOOST_REQUIRE(node::matmul_trusted::HasQuorum(
        competing_hash, tip->nHeight + 1));

    // Follow the attested sibling as best-header and advertise it from a
    // fresh peer so LastCommon / HAVE_DATA-unconnected state on the original
    // connection cannot mask skip-set erasure.
    {
        LOCK(::cs_main);
        CBlockIndex* competing_idx{
            m_node.chainman->m_blockman.LookupBlockIndex(competing_hash)};
        BOOST_REQUIRE(competing_idx != nullptr);
        m_node.chainman->SetBestHeader(competing_idx);
    }

    CNode source{/*id=*/212,
                 /*sock=*/nullptr,
                 CAddress{PeermanTestService(0x1200007f), NODE_NETWORK},
                 /*nKeyedNetGroupIn=*/0x23,
                 /*nLocalHostNonceIn=*/0,
                 CAddress{},
                 /*addrNameIn=*/"late-quorum-body-source",
                 ConnectionType::OUTBOUND_FULL_RELAY,
                 /*inbound_onion=*/false,
                 /*network_key=*/0};
    connman.Handshake(source, /*successfully_connected=*/true, services,
                      services, PROTOCOL_VERSION, /*relay_txs=*/true);
    connman.AddTestNode(source);
    connman.FlushSendBuffer(source);
    struct FinalizeSource {
        ConnmanTestMsg& connman;
        PeerManager& peerman;
        CNode& node;
        ~FinalizeSource()
        {
            peerman.FinalizeNode(node);
            connman.RemoveTestNode(node);
        }
    } finalize_source{connman, peerman, source};

    std::vector<CBlock> competing_headers{CBlock{competing.GetBlockHeader()}};
    BOOST_REQUIRE(connman.ReceiveMsgFrom(
        source, NetMsg::Make(NetMsgType::HEADERS,
                             TX_WITH_WITNESS(competing_headers))));
    source.fPauseSend = false;
    (void)connman.ProcessMessagesOnce(source);

    bool fetched{false};
    for (int i = 0; i < 10; ++i) {
        (void)peerman.SendMessages(&source);
        if (CountQueuedGetDataForHash(source, competing_hash) > 0 ||
            HasQueuedMessageType(source, NetMsgType::GETDATA)) {
            fetched = true;
            break;
        }
        CNodeStateStats source_stats;
        BOOST_REQUIRE(peerman.GetNodeStateStats(source.GetId(), source_stats));
        if (std::find(source_stats.vHeightInFlight.begin(),
                      source_stats.vHeightInFlight.end(),
                      tip->nHeight + 1) != source_stats.vHeightInFlight.end()) {
            fetched = true;
            break;
        }
        connman.FlushSendBuffer(source);
    }
    BOOST_CHECK(fetched);

    {
        LOCK(::cs_main);
        m_node.chainman->SetBestHeader(
            const_cast<CBlockIndex*>(m_node.chainman->ActiveTip()));
        CBlockIndex* followed_idx{
            m_node.chainman->m_blockman.LookupBlockIndex(followed.GetHash())};
        if (followed_idx != nullptr) {
            followed_idx->nStatus &= ~BLOCK_HAVE_DATA;
            followed_idx->nTx = 0;
            followed_idx->m_chain_tx_count = 0;
            m_node.chainman->ActiveChainstate().setBlockIndexCandidates.erase(
                followed_idx);
        }
    }
}

BOOST_AUTO_TEST_CASE(catchup_grandchild_persists_on_trusted_mirror)
{
    // Live 2026-08-15 (PR 105 comment 5302572644): tip-extending
    // grandchildren were HEADER_ONLY-skipped like competing siblings, so
    // the suffix never got HAVE_DATA and FindMostWorkChain spun. Immediate
    // competing siblings stay HEADER_ONLY (competing_sibling_stays_header_only).
    LOCK(NetEventsInterface::g_msgproc_mutex);

    node::matmul_trusted::ResetForTest();
    ResetSharedPeermanFixture(m_node);
    CKey signer;
    signer.MakeNewKey(/*fCompressed=*/true);
    matmul::trusted::StoreConfig config;
    config.chain_id = uint256::FromHex(std::string(64, '1')).value();
    config.replay_authority_context =
        uint256::FromHex(std::string(64, '2')).value();
    config.trusted_signers = {signer.GetPubKey()};
    config.threshold = 1;
    std::string error;
    BOOST_REQUIRE(node::matmul_trusted::Configure(
        std::move(config), /*trusted_mirror=*/true, /*serve=*/false,
        std::chrono::milliseconds{50}, error));
    BOOST_REQUIRE(node::matmul_trusted::IsTrustedMirror());
    struct MirrorReset {
        ~MirrorReset() { node::matmul_trusted::ResetForTest(); }
    } mirror_reset;

    ConnmanTestMsg& connman = static_cast<ConnmanTestMsg&>(*m_node.connman);
    PeerManager& peerman = *m_node.peerman;

    const CBlockIndex* tip{
        WITH_LOCK(::cs_main, return m_node.chainman->ActiveChain().Tip())};
    BOOST_REQUIRE(tip != nullptr);
    SetMockTime(std::chrono::seconds{tip->GetBlockTime() + 1});
    peerman.SetBestBlock(tip->nHeight, std::chrono::seconds{tip->GetBlockTime()});

    Consensus::Params& consensus = const_cast<Consensus::Params&>(
        m_node.chainman->GetParams().GetConsensus());
    auto restore_heights{SaveMatMulHeights(consensus)};
    ActivateRcAtTip(consensus, *tip);

    const ServiceFlags services{ServiceFlags(
        NODE_NETWORK | NODE_WITNESS | NODE_MATMUL_CONSENSUS |
        NODE_MATMUL_ATTESTATION_ARCHIVE)};
    CNode peer{/*id=*/222,
               /*sock=*/nullptr,
               CAddress{PeermanTestService(0x2200007f), NODE_NETWORK},
               /*nKeyedNetGroupIn=*/0x24,
               /*nLocalHostNonceIn=*/0,
               CAddress{},
               /*addrNameIn=*/"catchup-suffix-mirror",
               ConnectionType::OUTBOUND_FULL_RELAY,
               /*inbound_onion=*/false,
               /*network_key=*/0};
    connman.Handshake(peer, /*successfully_connected=*/true, services, services,
                      PROTOCOL_VERSION, /*relay_txs=*/true);
    connman.AddTestNode(peer);
    connman.FlushSendBuffer(peer);
    struct FinalizePeer {
        ConnmanTestMsg& connman;
        PeerManager& peerman;
        CNode& node;
        ~FinalizePeer()
        {
            peerman.FinalizeNode(node);
            connman.RemoveTestNode(node);
        }
    } finalize{connman, peerman, peer};

    CBlock child{MineTipChild(m_node, *tip, /*extra_time=*/0)};
    CBlock grandchild = node::BlockAssembler{
        m_node.chainman->ActiveChainstate(), nullptr, {}, m_node}
                            .CreateNewBlock()
                            ->block;
    grandchild.hashPrevBlock = child.GetHash();
    grandchild.nTime = child.nTime + 1;
    {
        CMutableTransaction coinbase{*grandchild.vtx[0]};
        coinbase.vin[0].scriptSig = CScript() << (tip->nHeight + 2) << OP_0;
        grandchild.vtx[0] = MakeTransactionRef(coinbase);
    }
    grandchild.hashMerkleRoot = BlockMerkleRoot(grandchild);
    BOOST_REQUIRE(MineHeaderForConsensus(
        grandchild, tip->nHeight + 2, m_node.chainman->GetConsensus(),
        5'000'000, child.GetBlockTime()));
    const uint256 grandchild_hash{grandchild.GetHash()};

    std::vector<CBlock> headers{CBlock{child.GetBlockHeader()},
                                CBlock{grandchild.GetBlockHeader()}};
    BOOST_REQUIRE(connman.ReceiveMsgFrom(
        peer, NetMsg::Make(NetMsgType::HEADERS, TX_WITH_WITNESS(headers))));
    peer.fPauseSend = false;
    (void)connman.ProcessMessagesOnce(peer);
    connman.FlushSendBuffer(peer);

    {
        DebugLogHelper no_header_only(
            "skipped ExactReplay GPU (competing near-tip P2P sibling",
            [](const std::string* line) {
                if (line != nullptr) {
                    throw std::runtime_error(
                        "catch-up grandchild must not take HEADER_ONLY skip");
                }
                return false;
            });
        BOOST_REQUIRE(connman.ReceiveMsgFrom(
            peer, NetMsg::Make(NetMsgType::BLOCK, TX_WITH_WITNESS(grandchild))));
        peer.fPauseSend = false;
        (void)connman.ProcessMessagesOnce(peer);
    }
    BOOST_CHECK(!peer.fDisconnect);
    {
        LOCK(::cs_main);
        const CBlockIndex* idx{
            m_node.chainman->m_blockman.LookupBlockIndex(grandchild_hash)};
        BOOST_REQUIRE(idx != nullptr);
        BOOST_CHECK(idx->nStatus & BLOCK_HAVE_DATA);
        BOOST_CHECK_EQUAL(idx->nHeight, tip->nHeight + 2);
        BOOST_CHECK(idx->GetAncestor(tip->nHeight) == tip);
    }

    NeutralizeUnconnectedHeaders(*Assert(m_node.chainman));
    peerman.ResetMatMulVerifyAdmissionForTest();
}

BOOST_AUTO_TEST_CASE(global_rc_budget_exhaustion_does_not_disconnect_honest_peer)
{
    LOCK(NetEventsInterface::g_msgproc_mutex);

    node::matmul_trusted::ResetForTest();
    ResetSharedPeermanFixture(m_node);
    ConnmanTestMsg& connman = static_cast<ConnmanTestMsg&>(*m_node.connman);
    PeerManager& peerman = *m_node.peerman;
    ResetGlobalMatMulRCBudgetForTest();

    const CBlockIndex* tip{
        WITH_LOCK(::cs_main, return m_node.chainman->ActiveChain().Tip())};
    BOOST_REQUIRE(tip != nullptr);
    SetMockTime(std::chrono::seconds{tip->GetBlockTime() + 1});
    peerman.SetBestBlock(tip->nHeight, std::chrono::seconds{tip->GetBlockTime()});

    Consensus::Params& consensus = const_cast<Consensus::Params&>(
        m_node.chainman->GetParams().GetConsensus());
    auto restore_heights{SaveMatMulHeights(consensus)};
    ActivateRcAtTip(consensus, *tip);
    consensus.nMatMulRCGlobalVerifyBudgetPerMin =
        MatMulRCWorkUnits(consensus, tip->nHeight + 1);
    consensus.nMatMulRCPeerVerifyBudgetPerMin =
        std::numeric_limits<uint32_t>::max();
    // Cap-one would retain the second body before consume_reserved_budget
    // sees the global window. Two pending slots lets DoS-F2 fire on the
    // rate debit instead of the lease.
    consensus.nMatMulRCMaxPendingVerifications = 2;

    PeermanBlockingVerify gate;
    peerman.InstallMatMulVerifyOverrideForTest(
        [&](const CBlock&, int32_t, std::optional<int64_t>) { return gate.Run(); });
    struct ClearGlobalOverride {
        PeerManager& peerman;
        ~ClearGlobalOverride() { peerman.InstallMatMulVerifyOverrideForTest({}); }
    } clear_global_override{peerman};

    const ServiceFlags services{ServiceFlags(NODE_NETWORK | NODE_WITNESS | NODE_MATMUL_CONSENSUS)};
    CNode occupier{/*id=*/203,
                   /*sock=*/nullptr,
                   CAddress{PeermanTestService(0x0300007f), NODE_NETWORK},
                   /*nKeyedNetGroupIn=*/0x33,
                   /*nLocalHostNonceIn=*/0,
                   CAddress{},
                   /*addrNameIn=*/"global-budget-occupier",
                   ConnectionType::OUTBOUND_FULL_RELAY,
                   /*inbound_onion=*/false,
                   /*network_key=*/0};
    CNode honest{/*id=*/204,
                 /*sock=*/nullptr,
                 CAddress{PeermanTestService(0x0400007f), NODE_NETWORK},
                 /*nKeyedNetGroupIn=*/0x44,
                 /*nLocalHostNonceIn=*/0,
                 CAddress{},
                 /*addrNameIn=*/"global-budget-honest",
                 ConnectionType::OUTBOUND_FULL_RELAY,
                 /*inbound_onion=*/false,
                 /*network_key=*/0};
    connman.Handshake(occupier, /*successfully_connected=*/true, services,
                      services, PROTOCOL_VERSION, /*relay_txs=*/true);
    connman.Handshake(honest, /*successfully_connected=*/true, services,
                      services, PROTOCOL_VERSION, /*relay_txs=*/true);
    connman.AddTestNode(occupier);
    connman.AddTestNode(honest);
    connman.FlushSendBuffer(occupier);
    connman.FlushSendBuffer(honest);
    struct FinalizePeers {
        ConnmanTestMsg& connman;
        PeerManager& peerman;
        CNode& occupier;
        CNode& honest;
        ~FinalizePeers()
        {
            peerman.FinalizeNode(occupier);
            peerman.FinalizeNode(honest);
            connman.RemoveTestNode(occupier);
            connman.RemoveTestNode(honest);
        }
    } finalize{connman, peerman, occupier, honest};

    CBlock first{MineTipChild(m_node, *tip, /*extra_time=*/0)};
    CBlock second{MineTipChild(m_node, *tip, /*extra_time=*/1)};
    BOOST_REQUIRE(first.GetHash() != second.GetHash());

    auto send_full = [&](CNode& node, const CBlock& block) {
        const auto ticket{GrindTicket(block.GetBlockHeader(), consensus.powLimit)};
        std::vector<CBlock> headers{CBlock{block.GetBlockHeader()}};
        BOOST_REQUIRE(connman.ReceiveMsgFrom(
            node, NetMsg::Make(NetMsgType::HEADERS, TX_WITH_WITNESS(headers))));
        node.fPauseSend = false;
        (void)connman.ProcessMessagesOnce(node);
        connman.FlushSendBuffer(node);
        BOOST_REQUIRE(connman.ReceiveMsgFrom(
            node, NetMsg::Make(NetMsgType::RCADMIT, ticket)));
        node.fPauseSend = false;
        (void)connman.ProcessMessagesOnce(node);
        connman.FlushSendBuffer(node);
        BOOST_REQUIRE(connman.ReceiveMsgFrom(
            node, NetMsg::Make(NetMsgType::BLOCK, TX_WITH_WITNESS(block))));
        node.fPauseSend = false;
        (void)connman.ProcessMessagesOnce(node);
    };
    send_full(occupier, first);
    BOOST_REQUIRE(PeermanWaitFor([&] { return gate.running.load() >= 1; }));
    send_full(honest, second);

    BOOST_CHECK(!honest.fDisconnect);
    BOOST_CHECK(!occupier.fDisconnect);
    BOOST_CHECK(peerman.HasMatMulRetainedBodyForTest(second.GetHash()));
    {
        LOCK(::cs_main);
        const CBlockIndex* idx{
            m_node.chainman->m_blockman.LookupBlockIndex(second.GetHash())};
        BOOST_REQUIRE(idx != nullptr);
        BOOST_CHECK_EQUAL(idx->nStatus & BLOCK_HAVE_DATA, 0);
    }
}

// EncDr pending-cap miss used to HEADER_ONLY-drop the body and disconnect.
// Delivered followed-chain bodies must be retained like Profile-1 RC.
BOOST_AUTO_TEST_CASE(encdr_pending_cap_retains_followed_chain_body)
{
    LOCK(NetEventsInterface::g_msgproc_mutex);

    ConnmanTestMsg& connman = static_cast<ConnmanTestMsg&>(*m_node.connman);
    PeerManager& peerman = *m_node.peerman;

    Consensus::Params& consensus = const_cast<Consensus::Params&>(
        m_node.chainman->GetParams().GetConsensus());
    const int32_t saved_rc = consensus.nMatMulRCHeight;
    const int32_t saved_v4 = consensus.nMatMulV4Height;
    const int32_t saved_bmx4c = consensus.nMatMulBMX4CHeight;
    const int32_t saved_drlt = consensus.nMatMulDRLTHeight;
    const int32_t saved_coupled = consensus.nMatMulRCCoupledHeight;
    const uint32_t saved_v4_dim = consensus.nMatMulV4Dimension;
    const uint32_t saved_cap = consensus.nMatMulMaxPendingVerifications;
    struct Restore {
        Consensus::Params& params;
        int32_t rc;
        int32_t v4;
        int32_t bmx4c;
        int32_t drlt;
        int32_t coupled;
        uint32_t v4_dim;
        uint32_t cap;
        ~Restore()
        {
            params.nMatMulRCHeight = rc;
            params.nMatMulV4Height = v4;
            params.nMatMulBMX4CHeight = bmx4c;
            params.nMatMulDRLTHeight = drlt;
            params.nMatMulRCCoupledHeight = coupled;
            params.nMatMulV4Dimension = v4_dim;
            params.nMatMulMaxPendingVerifications = cap;
        }
    } restore{consensus, saved_rc, saved_v4, saved_bmx4c, saved_drlt,
              saved_coupled, saved_v4_dim, saved_cap};

    const CBlockIndex* tip{
        WITH_LOCK(::cs_main, return m_node.chainman->ActiveChain().Tip())};
    BOOST_REQUIRE(tip != nullptr);
    const int32_t next_height{tip->nHeight + 1};
    consensus.nMatMulV4Height = next_height;
    consensus.nMatMulBMX4CHeight = next_height;
    consensus.nMatMulDRLTHeight = std::numeric_limits<int32_t>::max();
    consensus.nMatMulRCHeight = std::numeric_limits<int32_t>::max();
    consensus.nMatMulRCCoupledHeight = std::numeric_limits<int32_t>::max();
    consensus.nMatMulV4Dimension = 64;
    consensus.nMatMulMaxPendingVerifications = 0;
    peerman.SetBestBlock(tip->nHeight, std::chrono::seconds{tip->GetBlockTime()});
    BOOST_REQUIRE(consensus.IsMatMulV4Active(next_height));
    BOOST_REQUIRE(!consensus.IsMatMulRCFamilyActive(next_height));
    BOOST_REQUIRE(!consensus.IsDRLTActive(next_height));

    CBlock child = node::BlockAssembler{
        m_node.chainman->ActiveChainstate(), nullptr, {}, m_node}
                       .CreateNewBlock()
                       ->block;
    child.hashMerkleRoot = BlockMerkleRoot(child);
    BOOST_REQUIRE(MineHeaderForConsensus(
        child, next_height, m_node.chainman->GetConsensus(), 5'000'000,
        tip->GetMedianTimePast()));

    const ServiceFlags services{ServiceFlags(NODE_NETWORK | NODE_WITNESS)};
    CNode peer{/*id=*/221,
               /*sock=*/nullptr,
               CAddress{},
               /*nKeyedNetGroupIn=*/0,
               /*nLocalHostNonceIn=*/0,
               CAddress{},
               /*addrNameIn=*/"encdr-cap-source",
               ConnectionType::OUTBOUND_FULL_RELAY,
               /*inbound_onion=*/false,
               /*network_key=*/0};
    connman.Handshake(peer, /*successfully_connected=*/true, services, services,
                      PROTOCOL_VERSION, /*relay_txs=*/true);
    connman.AddTestNode(peer);
    connman.FlushSendBuffer(peer);
    struct FinalizePeer {
        ConnmanTestMsg& connman;
        PeerManager& peerman;
        CNode& node;
        ~FinalizePeer()
        {
            peerman.FinalizeNode(node);
            connman.RemoveTestNode(node);
        }
    } finalize{connman, peerman, peer};

    std::vector<CBlock> headers{CBlock{child.GetBlockHeader()}};
    BOOST_REQUIRE(connman.ReceiveMsgFrom(
        peer, NetMsg::Make(NetMsgType::HEADERS, TX_WITH_WITNESS(headers))));
    peer.fPauseSend = false;
    (void)connman.ProcessMessagesOnce(peer);
    BOOST_CHECK(peerman.SendMessages(&peer));
    BOOST_REQUIRE(HasQueuedMessageType(peer, NetMsgType::GETDATA));
    connman.FlushSendBuffer(peer);

    {
        ASSERT_DEBUG_LOG("Deferring peer=");
        ASSERT_DEBUG_LOG("MatMul pending verification cap reached");
        ASSERT_DEBUG_LOG("Stored budget-deferred body");
        DebugLogHelper no_disconnect(
            "Disconnecting peer=", [](const std::string* line) {
                if (line != nullptr &&
                    line->find("pending verification cap") != std::string::npos) {
                    throw std::runtime_error(
                        "pending cap still disconnects the delivering peer");
                }
                return false;
            });
        BOOST_REQUIRE(connman.ReceiveMsgFrom(
            peer, NetMsg::Make(NetMsgType::BLOCK, TX_WITH_WITNESS(child))));
        peer.fPauseSend = false;
        (void)connman.ProcessMessagesOnce(peer);
    }
    BOOST_CHECK(!peer.fDisconnect);
    BOOST_CHECK(peerman.HasMatMulRetainedBodyForTest(child.GetHash()));

    const CBlockIndex* indexed{WITH_LOCK(
        ::cs_main,
        return m_node.chainman->m_blockman.LookupBlockIndex(child.GetHash()))};
    BOOST_REQUIRE(indexed != nullptr);
    BOOST_CHECK_EQUAL(indexed->nHeight, next_height);
    BOOST_CHECK_EQUAL(indexed->nStatus & BLOCK_HAVE_DATA, 0);

    // Skip-fetch: the retained body must not produce an unbounded getdata
    // storm while the cap stays exhausted.
    connman.FlushSendBuffer(peer);
    for (int i = 0; i < 5; ++i) {
        BOOST_CHECK(peerman.SendMessages(&peer));
        BOOST_CHECK(!HasQueuedMessageType(peer, NetMsgType::GETDATA));
        BOOST_CHECK(!peer.fDisconnect);
    }
}

BOOST_AUTO_TEST_CASE(rc_pending_cap_still_retains_for_retry)
{
    LOCK(NetEventsInterface::g_msgproc_mutex);

    ConnmanTestMsg& connman = static_cast<ConnmanTestMsg&>(*m_node.connman);
    PeerManager& peerman = *m_node.peerman;

    Consensus::Params& consensus = const_cast<Consensus::Params&>(
        m_node.chainman->GetParams().GetConsensus());
    const int32_t saved_rc = consensus.nMatMulRCHeight;
    const int32_t saved_v4 = consensus.nMatMulV4Height;
    const int32_t saved_bmx4c = consensus.nMatMulBMX4CHeight;
    const int32_t saved_drlt = consensus.nMatMulDRLTHeight;
    const int32_t saved_coupled = consensus.nMatMulRCCoupledHeight;
    const uint32_t saved_cap = consensus.nMatMulRCMaxPendingVerifications;
    struct Restore {
        Consensus::Params& params;
        int32_t rc;
        int32_t v4;
        int32_t bmx4c;
        int32_t drlt;
        int32_t coupled;
        uint32_t cap;
        ~Restore()
        {
            params.nMatMulRCHeight = rc;
            params.nMatMulV4Height = v4;
            params.nMatMulBMX4CHeight = bmx4c;
            params.nMatMulDRLTHeight = drlt;
            params.nMatMulRCCoupledHeight = coupled;
            params.nMatMulRCMaxPendingVerifications = cap;
        }
    } restore{consensus, saved_rc, saved_v4, saved_bmx4c, saved_drlt,
              saved_coupled, saved_cap};

    const CBlockIndex* tip{
        WITH_LOCK(::cs_main, return m_node.chainman->ActiveChain().Tip())};
    BOOST_REQUIRE(tip != nullptr);
    const int32_t next_height{tip->nHeight + 1};
    consensus.nMatMulV4Height = next_height;
    consensus.nMatMulBMX4CHeight = next_height;
    consensus.nMatMulDRLTHeight = std::numeric_limits<int32_t>::max();
    consensus.nMatMulRCHeight = next_height;
    consensus.nMatMulRCCoupledHeight = std::numeric_limits<int32_t>::max();
    consensus.nMatMulRCMaxPendingVerifications = 0;
    peerman.SetBestBlock(tip->nHeight, std::chrono::seconds{tip->GetBlockTime()});
    BOOST_REQUIRE(consensus.IsMatMulRCFamilyActive(next_height));

    CBlock child = node::BlockAssembler{
        m_node.chainman->ActiveChainstate(), nullptr, {}, m_node}
                       .CreateNewBlock()
                       ->block;
    child.hashMerkleRoot = BlockMerkleRoot(child);
    BOOST_REQUIRE(MineHeaderForConsensus(
        child, next_height, m_node.chainman->GetConsensus(), 5'000'000,
        tip->GetMedianTimePast()));

    const ServiceFlags services{ServiceFlags(NODE_NETWORK | NODE_WITNESS)};
    CNode peer{/*id=*/222,
               /*sock=*/nullptr,
               CAddress{},
               /*nKeyedNetGroupIn=*/0,
               /*nLocalHostNonceIn=*/0,
               CAddress{},
               /*addrNameIn=*/"rc-cap-source",
               ConnectionType::OUTBOUND_FULL_RELAY,
               /*inbound_onion=*/false,
               /*network_key=*/0};
    connman.Handshake(peer, /*successfully_connected=*/true, services, services,
                      PROTOCOL_VERSION, /*relay_txs=*/true);
    connman.AddTestNode(peer);
    connman.FlushSendBuffer(peer);
    struct FinalizePeer {
        ConnmanTestMsg& connman;
        PeerManager& peerman;
        CNode& node;
        ~FinalizePeer()
        {
            peerman.FinalizeNode(node);
            connman.RemoveTestNode(node);
        }
    } finalize{connman, peerman, peer};

    std::vector<CBlock> headers{CBlock{child.GetBlockHeader()}};
    BOOST_REQUIRE(connman.ReceiveMsgFrom(
        peer, NetMsg::Make(NetMsgType::HEADERS, TX_WITH_WITNESS(headers))));
    peer.fPauseSend = false;
    (void)connman.ProcessMessagesOnce(peer);
    BOOST_CHECK(peerman.SendMessages(&peer));
    connman.FlushSendBuffer(peer);

    {
        ASSERT_DEBUG_LOG("Deferring peer=");
        ASSERT_DEBUG_LOG("MatMul pending verification cap reached");
        ASSERT_DEBUG_LOG("Stored budget-deferred body");
        DebugLogHelper no_disconnect(
            "Disconnecting peer=", [](const std::string* line) {
                if (line != nullptr &&
                    line->find("pending verification cap") != std::string::npos) {
                    throw std::runtime_error(
                        "pending cap still disconnects the delivering peer");
                }
                return false;
            });
        BOOST_REQUIRE(connman.ReceiveMsgFrom(
            peer, NetMsg::Make(NetMsgType::BLOCK, TX_WITH_WITNESS(child))));
        peer.fPauseSend = false;
        (void)connman.ProcessMessagesOnce(peer);
    }
    BOOST_CHECK(!peer.fDisconnect);
    BOOST_CHECK(peerman.HasMatMulRetainedBodyForTest(child.GetHash()));
    {
        LOCK(::cs_main);
        const CBlockIndex* indexed{
            m_node.chainman->m_blockman.LookupBlockIndex(child.GetHash())};
        BOOST_REQUIRE(indexed != nullptr);
        BOOST_CHECK_EQUAL(indexed->nStatus & BLOCK_HAVE_DATA, 0);
    }

    connman.FlushSendBuffer(peer);
    for (int i = 0; i < 5; ++i) {
        BOOST_CHECK(peerman.SendMessages(&peer));
        BOOST_CHECK(!HasQueuedMessageType(peer, NetMsgType::GETDATA));
        BOOST_CHECK(!peer.fDisconnect);
    }
}

// Local signer / miner must not spend ExactReplay GPU on a competing EncDr
// sibling. HEADER_ONLY remains the policy; the pending-cap retain path must
// not reopen that GPU.
BOOST_AUTO_TEST_CASE(encdr_competing_sibling_does_not_steal_miner_gpu)
{
    LOCK(NetEventsInterface::g_msgproc_mutex);

    node::matmul_trusted::ResetForTest();
    CKey signer;
    signer.MakeNewKey(/*fCompressed=*/true);
    matmul::trusted::StoreConfig config;
    config.chain_id = uint256::FromHex(std::string(64, '1')).value();
    config.replay_authority_context =
        uint256::FromHex(std::string(64, '2')).value();
    config.trusted_signers = {signer.GetPubKey()};
    config.threshold = 1;
    config.local_signer = signer;
    std::string error;
    BOOST_REQUIRE(node::matmul_trusted::Configure(
        std::move(config), /*trusted_mirror=*/false, /*serve=*/false,
        std::chrono::milliseconds{50}, error));
    BOOST_REQUIRE(node::matmul_trusted::HasLocalSigner());
    struct SignerReset {
        ~SignerReset() { node::matmul_trusted::ResetForTest(); }
    } signer_reset;

    ConnmanTestMsg& connman = static_cast<ConnmanTestMsg&>(*m_node.connman);
    PeerManager& peerman = *m_node.peerman;

    Consensus::Params& consensus = const_cast<Consensus::Params&>(
        m_node.chainman->GetParams().GetConsensus());
    const int32_t saved_rc = consensus.nMatMulRCHeight;
    const int32_t saved_v4 = consensus.nMatMulV4Height;
    const int32_t saved_bmx4c = consensus.nMatMulBMX4CHeight;
    const int32_t saved_drlt = consensus.nMatMulDRLTHeight;
    const int32_t saved_coupled = consensus.nMatMulRCCoupledHeight;
    const uint32_t saved_v4_dim = consensus.nMatMulV4Dimension;
    struct Restore {
        Consensus::Params& params;
        int32_t rc;
        int32_t v4;
        int32_t bmx4c;
        int32_t drlt;
        int32_t coupled;
        uint32_t v4_dim;
        ~Restore()
        {
            params.nMatMulRCHeight = rc;
            params.nMatMulV4Height = v4;
            params.nMatMulBMX4CHeight = bmx4c;
            params.nMatMulDRLTHeight = drlt;
            params.nMatMulRCCoupledHeight = coupled;
            params.nMatMulV4Dimension = v4_dim;
        }
    } restore{consensus, saved_rc, saved_v4, saved_bmx4c, saved_drlt,
              saved_coupled, saved_v4_dim};

    const CBlockIndex* tip{
        WITH_LOCK(::cs_main, return m_node.chainman->ActiveChain().Tip())};
    BOOST_REQUIRE(tip != nullptr);
    const int32_t next_height{tip->nHeight + 1};
    consensus.nMatMulV4Height = next_height;
    consensus.nMatMulBMX4CHeight = next_height;
    consensus.nMatMulDRLTHeight = std::numeric_limits<int32_t>::max();
    consensus.nMatMulRCHeight = std::numeric_limits<int32_t>::max();
    consensus.nMatMulRCCoupledHeight = std::numeric_limits<int32_t>::max();
    consensus.nMatMulV4Dimension = 64;
    peerman.SetBestBlock(tip->nHeight, std::chrono::seconds{tip->GetBlockTime()});

    auto mine_child = [&](uint32_t time_offset) {
        CBlock block = node::BlockAssembler{
            m_node.chainman->ActiveChainstate(), nullptr, {}, m_node}
                           .CreateNewBlock()
                           ->block;
        block.nTime = tip->GetBlockTime() + time_offset;
        block.hashMerkleRoot = BlockMerkleRoot(block);
        BOOST_REQUIRE(MineHeaderForConsensus(
            block, next_height, m_node.chainman->GetConsensus(), 5'000'000,
            tip->GetMedianTimePast()));
        return block;
    };
    CBlock adopted = mine_child(1);
    CBlock competing = mine_child(2);
    BOOST_REQUIRE(adopted.GetHash() != competing.GetHash());
    BOOST_REQUIRE(adopted.hashPrevBlock == tip->GetBlockHash());
    BOOST_REQUIRE(competing.hashPrevBlock == tip->GetBlockHash());

    BOOST_REQUIRE(m_node.chainman->ProcessNewBlock(
        std::make_shared<const CBlock>(adopted), /*force_processing=*/true,
        /*min_pow_checked=*/true, nullptr));
    BOOST_CHECK_EQUAL(
        WITH_LOCK(::cs_main,
                  return m_node.chainman->ActiveChain().Tip()->GetBlockHash()),
        adopted.GetHash());

    const ServiceFlags services{ServiceFlags(NODE_NETWORK | NODE_WITNESS)};
    CNode peer{/*id=*/223,
               /*sock=*/nullptr,
               CAddress{},
               /*nKeyedNetGroupIn=*/0,
               /*nLocalHostNonceIn=*/0,
               CAddress{},
               /*addrNameIn=*/"encdr-competing-sibling",
               ConnectionType::INBOUND,
               /*inbound_onion=*/false,
               /*network_key=*/0};
    connman.Handshake(peer, /*successfully_connected=*/true, services, services,
                      PROTOCOL_VERSION, /*relay_txs=*/true);
    connman.AddTestNode(peer);
    connman.FlushSendBuffer(peer);
    peer.fPauseSend = false;
    struct FinalizePeer {
        ConnmanTestMsg& connman;
        PeerManager& peerman;
        CNode& node;
        ~FinalizePeer()
        {
            peerman.FinalizeNode(node);
            connman.RemoveTestNode(node);
        }
    } finalize{connman, peerman, peer};

    std::vector<CBlock> headers{CBlock{competing.GetBlockHeader()}};
    BOOST_REQUIRE(connman.ReceiveMsgFrom(
        peer, NetMsg::Make(NetMsgType::HEADERS, TX_WITH_WITNESS(headers))));
    peer.fPauseSend = false;
    (void)connman.ProcessMessagesOnce(peer);

    {
        ASSERT_DEBUG_LOG("skipped ExactReplay GPU (competing near-tip P2P sibling");
        BOOST_REQUIRE(connman.ReceiveMsgFrom(
            peer, NetMsg::Make(NetMsgType::BLOCK, TX_WITH_WITNESS(competing))));
        peer.fPauseSend = false;
        (void)connman.ProcessMessagesOnce(peer);
    }
    BOOST_CHECK(!peer.fDisconnect);
    BOOST_CHECK(!peerman.HasMatMulRetainedBodyForTest(competing.GetHash()));
    BOOST_CHECK_EQUAL(
        WITH_LOCK(::cs_main,
                  return m_node.chainman->ActiveChain().Tip()->GetBlockHash()),
        adopted.GetHash());
    {
        LOCK(::cs_main);
        const CBlockIndex* idx{
            m_node.chainman->m_blockman.LookupBlockIndex(competing.GetHash())};
        BOOST_REQUIRE(idx != nullptr);
        BOOST_CHECK_EQUAL(idx->nStatus & BLOCK_HAVE_DATA, 0);
    }

    connman.FlushSendBuffer(peer);
    for (int i = 0; i < 5; ++i) {
        BOOST_CHECK(peerman.SendMessages(&peer));
        BOOST_CHECK(!HasQueuedMessageType(peer, NetMsgType::GETDATA));
        BOOST_CHECK(!peer.fDisconnect);
    }
}

// Consensus + local signing key must ExactReplay the followed tip-child so
// this node can SignAuthoritative and IBD. Skipping GPU used to HEADER_ONLY
// every next body (PR 105 review of 1eb8caf3). Competing siblings stay
// HEADER_ONLY; that is covered by encdr_competing_sibling_does_not_steal_miner_gpu.
BOOST_AUTO_TEST_CASE(local_signer_exactreplays_followed_tip_child_for_ibd)
{
    LOCK(NetEventsInterface::g_msgproc_mutex);

    node::matmul_trusted::ResetForTest();
    CKey signer;
    signer.MakeNewKey(/*fCompressed=*/true);
    matmul::trusted::StoreConfig config;
    config.chain_id = uint256::FromHex(std::string(64, '1')).value();
    config.replay_authority_context =
        uint256::FromHex(std::string(64, '2')).value();
    config.trusted_signers = {signer.GetPubKey()};
    config.threshold = 1;
    config.local_signer = signer;
    std::string error;
    BOOST_REQUIRE(node::matmul_trusted::Configure(
        std::move(config), /*trusted_mirror=*/false, /*serve=*/true,
        std::chrono::milliseconds{50}, error));
    BOOST_REQUIRE(node::matmul_trusted::HasLocalSigner());
    BOOST_REQUIRE(!node::matmul_trusted::IsTrustedMirror());
    struct SignerReset {
        ~SignerReset() { node::matmul_trusted::ResetForTest(); }
    } signer_reset;

    ConnmanTestMsg& connman = static_cast<ConnmanTestMsg&>(*m_node.connman);
    PeerManager& peerman = *m_node.peerman;
    peerman.InstallMatMulVerifyOverrideForTest(
        [&](const CBlock&, int32_t, std::optional<int64_t>) { return true; });
    struct ClearOverride {
        PeerManager& peerman;
        ~ClearOverride() { peerman.InstallMatMulVerifyOverrideForTest({}); }
    } clear_override{peerman};

    Consensus::Params& consensus = const_cast<Consensus::Params&>(
        m_node.chainman->GetParams().GetConsensus());
    auto restore_heights{SaveMatMulHeights(consensus)};

    const CBlockIndex* tip{
        WITH_LOCK(::cs_main, return m_node.chainman->ActiveChain().Tip())};
    BOOST_REQUIRE(tip != nullptr);
    SetMockTime(std::chrono::seconds{tip->GetBlockTime() + 1});
    ActivateRcAtTip(consensus, *tip);
    peerman.SetBestBlock(tip->nHeight, std::chrono::seconds{tip->GetBlockTime()});

    CBlock child{MineTipChild(m_node, *tip, /*extra_time=*/0)};
    const uint256 child_hash{child.GetHash()};

    const ServiceFlags services{ServiceFlags(
        NODE_NETWORK | NODE_WITNESS | NODE_MATMUL_CONSENSUS)};
    CNode peer{/*id=*/206,
               /*sock=*/nullptr,
               CAddress{PeermanTestService(0x0600007f), NODE_NETWORK},
               /*nKeyedNetGroupIn=*/0x66,
               /*nLocalHostNonceIn=*/0,
               CAddress{},
               /*addrNameIn=*/"signer-ibd-source",
               ConnectionType::OUTBOUND_FULL_RELAY,
               /*inbound_onion=*/false,
               /*network_key=*/0};
    connman.Handshake(peer, /*successfully_connected=*/true, services, services,
                      PROTOCOL_VERSION, /*relay_txs=*/true);
    connman.AddTestNode(peer);
    connman.FlushSendBuffer(peer);
    struct FinalizePeer {
        ConnmanTestMsg& connman;
        PeerManager& peerman;
        CNode& node;
        ~FinalizePeer()
        {
            peerman.FinalizeNode(node);
            connman.RemoveTestNode(node);
        }
    } finalize{connman, peerman, peer};

    std::vector<CBlock> headers{CBlock{child.GetBlockHeader()}};
    BOOST_REQUIRE(connman.ReceiveMsgFrom(
        peer, NetMsg::Make(NetMsgType::HEADERS, TX_WITH_WITNESS(headers))));
    peer.fPauseSend = false;
    (void)connman.ProcessMessagesOnce(peer);
    BOOST_CHECK(peerman.SendMessages(&peer));
    CNodeStateStats after_headers;
    BOOST_REQUIRE(peerman.GetNodeStateStats(peer.GetId(), after_headers));
    BOOST_REQUIRE(
        CountQueuedGetDataForHash(peer, child_hash) > 0 ||
        HasQueuedMessageType(peer, NetMsgType::GETDATA) ||
        std::find(after_headers.vHeightInFlight.begin(),
                  after_headers.vHeightInFlight.end(),
                  tip->nHeight + 1) != after_headers.vHeightInFlight.end());
    connman.FlushSendBuffer(peer);

    BOOST_REQUIRE(connman.ReceiveMsgFrom(
        peer, NetMsg::Make(NetMsgType::BLOCK, TX_WITH_WITNESS(child))));
    peer.fPauseSend = false;
    (void)connman.ProcessMessagesOnce(peer);
    BOOST_CHECK(!peer.fDisconnect);

    BOOST_REQUIRE(PeermanWaitFor([&] {
        LOCK(::cs_main);
        const CBlockIndex* idx{
            m_node.chainman->m_blockman.LookupBlockIndex(child_hash)};
        return idx != nullptr && (idx->nStatus & BLOCK_HAVE_DATA) != 0;
    }));
    BOOST_CHECK(!peerman.HasMatMulRetainedBodyForTest(child_hash));

    for (int i = 0; i < 5; ++i) {
        (void)peerman.SendMessages(&peer);
        m_node.validation_signals->SyncWithValidationInterfaceQueue();
        if (WITH_LOCK(::cs_main, {
                const CBlockIndex* idx{
                    m_node.chainman->m_blockman.LookupBlockIndex(child_hash)};
                return idx != nullptr &&
                       m_node.chainman->ActiveChain().Contains(idx);
            })) {
            break;
        }
    }
    BOOST_CHECK(WITH_LOCK(::cs_main, {
        const CBlockIndex* idx{
            m_node.chainman->m_blockman.LookupBlockIndex(child_hash)};
        return idx != nullptr && m_node.chainman->ActiveChain().Contains(idx);
    }));

    CBlockIndex* connected{WITH_LOCK(::cs_main, {
        CBlockIndex* idx{
            m_node.chainman->m_blockman.LookupBlockIndex(child_hash)};
        return (idx != nullptr && m_node.chainman->ActiveChain().Contains(idx))
                   ? idx
                   : nullptr;
    })};
    if (connected != nullptr) {
        BlockValidationState invalidate_state;
        (void)m_node.chainman->ActiveChainstate().InvalidateBlock(
            invalidate_state, connected);
    }
    {
        LOCK(::cs_main);
        m_node.chainman->SetBestHeader(
            const_cast<CBlockIndex*>(m_node.chainman->ActiveTip()));
    }
}

// Independent confirm of PR 105 comments 5301483741 / 5301685574 on
// 366fa7d1: a CONSENSUS node with trusted pubkeys but no local signing
// key ExactReplays and connects the followed tip-child. The old
// HasLocalSigner() gate on RetryMatMulDeferredBodies / GPU spend left
// this role frozen at the parent while the signed frontier moved.
BOOST_AUTO_TEST_CASE(signer_free_consensus_exactreplays_followed_tip_child)
{
    LOCK(NetEventsInterface::g_msgproc_mutex);

    node::matmul_trusted::ResetForTest();
    ResetSharedPeermanFixture(m_node);
    CKey signer;
    signer.MakeNewKey(/*fCompressed=*/true);
    matmul::trusted::StoreConfig config;
    config.chain_id = uint256::FromHex(std::string(64, '1')).value();
    config.replay_authority_context =
        uint256::FromHex(std::string(64, '2')).value();
    config.trusted_signers = {signer.GetPubKey()};
    config.threshold = 1;
    std::string error;
    BOOST_REQUIRE(node::matmul_trusted::Configure(
        std::move(config), /*trusted_mirror=*/false, /*serve=*/false,
        std::chrono::milliseconds{50}, error));
    BOOST_REQUIRE(node::matmul_trusted::IsConfigured());
    BOOST_REQUIRE(!node::matmul_trusted::HasLocalSigner());
    BOOST_REQUIRE(!node::matmul_trusted::IsTrustedMirror());
    struct VerifierReset {
        ~VerifierReset() { node::matmul_trusted::ResetForTest(); }
    } verifier_reset;

    auto& mode = const_cast<kernel::MatMulValidationMode&>(
        m_node.chainman->m_options.matmul_validation_mode);
    const auto saved_mode{mode};
    struct RestoreMode {
        kernel::MatMulValidationMode& mode;
        kernel::MatMulValidationMode saved;
        ~RestoreMode() { mode = saved; }
    } restore_mode{mode, saved_mode};
    mode = kernel::MatMulValidationMode::CONSENSUS;

    ConnmanTestMsg& connman = static_cast<ConnmanTestMsg&>(*m_node.connman);
    PeerManager& peerman = *m_node.peerman;
    peerman.InstallMatMulVerifyOverrideForTest(
        [&](const CBlock&, int32_t, std::optional<int64_t>) { return true; });
    struct ClearOverride {
        PeerManager& peerman;
        ~ClearOverride() { peerman.InstallMatMulVerifyOverrideForTest({}); }
    } clear_override{peerman};

    Consensus::Params& consensus = const_cast<Consensus::Params&>(
        m_node.chainman->GetParams().GetConsensus());
    auto restore_heights{SaveMatMulHeights(consensus)};

    const CBlockIndex* tip{
        WITH_LOCK(::cs_main, return m_node.chainman->ActiveChain().Tip())};
    BOOST_REQUIRE(tip != nullptr);
    SetMockTime(std::chrono::seconds{tip->GetBlockTime() + 1});
    ActivateRcAtTip(consensus, *tip);
    peerman.SetBestBlock(tip->nHeight, std::chrono::seconds{tip->GetBlockTime()});

    CBlock child{MineTipChild(m_node, *tip, /*extra_time=*/0)};
    const uint256 child_hash{child.GetHash()};

    const ServiceFlags services{ServiceFlags(
        NODE_NETWORK | NODE_WITNESS | NODE_MATMUL_CONSENSUS)};
    CNode peer{/*id=*/207,
               /*sock=*/nullptr,
               CAddress{PeermanTestService(0x0700007f), NODE_NETWORK},
               /*nKeyedNetGroupIn=*/0x67,
               /*nLocalHostNonceIn=*/0,
               CAddress{},
               /*addrNameIn=*/"signer-free-ibd-source",
               ConnectionType::OUTBOUND_FULL_RELAY,
               /*inbound_onion=*/false,
               /*network_key=*/0};
    connman.Handshake(peer, /*successfully_connected=*/true, services, services,
                      PROTOCOL_VERSION, /*relay_txs=*/true);
    connman.AddTestNode(peer);
    connman.FlushSendBuffer(peer);
    struct FinalizePeer {
        ConnmanTestMsg& connman;
        PeerManager& peerman;
        CNode& node;
        ~FinalizePeer()
        {
            peerman.FinalizeNode(node);
            connman.RemoveTestNode(node);
        }
    } finalize{connman, peerman, peer};

    std::vector<CBlock> headers{CBlock{child.GetBlockHeader()}};
    BOOST_REQUIRE(connman.ReceiveMsgFrom(
        peer, NetMsg::Make(NetMsgType::HEADERS, TX_WITH_WITNESS(headers))));
    peer.fPauseSend = false;
    (void)connman.ProcessMessagesOnce(peer);
    BOOST_CHECK(peerman.SendMessages(&peer));
    CNodeStateStats after_headers;
    BOOST_REQUIRE(peerman.GetNodeStateStats(peer.GetId(), after_headers));
    BOOST_REQUIRE(
        CountQueuedGetDataForHash(peer, child_hash) > 0 ||
        HasQueuedMessageType(peer, NetMsgType::GETDATA) ||
        std::find(after_headers.vHeightInFlight.begin(),
                  after_headers.vHeightInFlight.end(),
                  tip->nHeight + 1) != after_headers.vHeightInFlight.end());
    connman.FlushSendBuffer(peer);

    BOOST_REQUIRE(connman.ReceiveMsgFrom(
        peer, NetMsg::Make(NetMsgType::BLOCK, TX_WITH_WITNESS(child))));
    peer.fPauseSend = false;
    (void)connman.ProcessMessagesOnce(peer);
    BOOST_CHECK(!peer.fDisconnect);

    BOOST_REQUIRE(PeermanWaitFor([&] {
        LOCK(::cs_main);
        const CBlockIndex* idx{
            m_node.chainman->m_blockman.LookupBlockIndex(child_hash)};
        return idx != nullptr && (idx->nStatus & BLOCK_HAVE_DATA) != 0;
    }));

    for (int i = 0; i < 5; ++i) {
        (void)peerman.SendMessages(&peer);
        m_node.validation_signals->SyncWithValidationInterfaceQueue();
        if (WITH_LOCK(::cs_main, {
                const CBlockIndex* idx{
                    m_node.chainman->m_blockman.LookupBlockIndex(child_hash)};
                return idx != nullptr &&
                       m_node.chainman->ActiveChain().Contains(idx);
            })) {
            break;
        }
    }
    BOOST_CHECK(WITH_LOCK(::cs_main, {
        const CBlockIndex* idx{
            m_node.chainman->m_blockman.LookupBlockIndex(child_hash)};
        return idx != nullptr && m_node.chainman->ActiveChain().Contains(idx);
    }));

    CBlockIndex* connected{WITH_LOCK(::cs_main, {
        CBlockIndex* idx{
            m_node.chainman->m_blockman.LookupBlockIndex(child_hash)};
        return (idx != nullptr && m_node.chainman->ActiveChain().Contains(idx))
                   ? idx
                   : nullptr;
    })};
    if (connected != nullptr) {
        BlockValidationState invalidate_state;
        (void)m_node.chainman->ActiveChainstate().InvalidateBlock(
            invalidate_state, connected);
    }
    {
        LOCK(::cs_main);
        m_node.chainman->SetBestHeader(
            const_cast<CBlockIndex*>(m_node.chainman->ActiveTip()));
    }
}

// Restart livelock 5301483741: HAVE_DATA followed child is not in the
// active chain (AcceptBlock early-returns on HAVE_DATA). Scheduler
// RetryMatMulDeferredBodies must re-admit it without HasLocalSigner().
BOOST_AUTO_TEST_CASE(signer_free_consensus_readmits_persisted_have_data_child)
{
    node::matmul_trusted::ResetForTest();
    ResetSharedPeermanFixture(m_node);
    CKey signer;
    signer.MakeNewKey(/*fCompressed=*/true);
    matmul::trusted::StoreConfig config;
    config.chain_id = uint256::FromHex(std::string(64, '1')).value();
    config.replay_authority_context =
        uint256::FromHex(std::string(64, '2')).value();
    config.trusted_signers = {signer.GetPubKey()};
    config.threshold = 1;
    std::string error;
    BOOST_REQUIRE(node::matmul_trusted::Configure(
        std::move(config), /*trusted_mirror=*/false, /*serve=*/false,
        std::chrono::milliseconds{50}, error));
    BOOST_REQUIRE(!node::matmul_trusted::HasLocalSigner());
    BOOST_REQUIRE(!node::matmul_trusted::IsTrustedMirror());
    struct VerifierReset {
        ~VerifierReset() { node::matmul_trusted::ResetForTest(); }
    } verifier_reset;

    auto& mode = const_cast<kernel::MatMulValidationMode&>(
        m_node.chainman->m_options.matmul_validation_mode);
    const auto saved_mode{mode};
    struct RestoreMode {
        kernel::MatMulValidationMode& mode;
        kernel::MatMulValidationMode saved;
        ~RestoreMode() { mode = saved; }
    } restore_mode{mode, saved_mode};
    mode = kernel::MatMulValidationMode::CONSENSUS;

    PeerManager& peerman = *m_node.peerman;
    peerman.InstallMatMulVerifyOverrideForTest(
        [&](const CBlock&, int32_t, std::optional<int64_t>) { return true; });
    struct ClearOverride {
        PeerManager& peerman;
        ~ClearOverride() { peerman.InstallMatMulVerifyOverrideForTest({}); }
    } clear_override{peerman};

    Consensus::Params& consensus = const_cast<Consensus::Params&>(
        m_node.chainman->GetParams().GetConsensus());
    auto restore_heights{SaveMatMulHeights(consensus)};

    uint256 child_hash;
    CBlockIndex* child_index{nullptr};
    {
        LOCK(NetEventsInterface::g_msgproc_mutex);
        ConnmanTestMsg& connman = static_cast<ConnmanTestMsg&>(*m_node.connman);
        const CBlockIndex* tip{
            WITH_LOCK(::cs_main, return m_node.chainman->ActiveChain().Tip())};
        BOOST_REQUIRE(tip != nullptr);
        SetMockTime(std::chrono::seconds{tip->GetBlockTime() + 1});
        ActivateRcAtTip(consensus, *tip);
        peerman.SetBestBlock(tip->nHeight, std::chrono::seconds{tip->GetBlockTime()});

        CBlock child{MineTipChild(m_node, *tip, /*extra_time=*/0)};
        child_hash = child.GetHash();

        const ServiceFlags services{ServiceFlags(
            NODE_NETWORK | NODE_WITNESS | NODE_MATMUL_CONSENSUS)};
        CNode peer{/*id=*/208,
                   /*sock=*/nullptr,
                   CAddress{PeermanTestService(0x0800007f), NODE_NETWORK},
                   /*nKeyedNetGroupIn=*/0x68,
                   /*nLocalHostNonceIn=*/0,
                   CAddress{},
                   /*addrNameIn=*/"signer-free-restart-source",
                   ConnectionType::OUTBOUND_FULL_RELAY,
                   /*inbound_onion=*/false,
                   /*network_key=*/0};
        connman.Handshake(peer, /*successfully_connected=*/true, services,
                          services, PROTOCOL_VERSION, /*relay_txs=*/true);
        connman.AddTestNode(peer);
        connman.FlushSendBuffer(peer);
        struct FinalizePeer {
            ConnmanTestMsg& connman;
            PeerManager& peerman;
            CNode& node;
            ~FinalizePeer()
            {
                peerman.FinalizeNode(node);
                connman.RemoveTestNode(node);
            }
        } finalize{connman, peerman, peer};

        std::vector<CBlock> headers{CBlock{child.GetBlockHeader()}};
        BOOST_REQUIRE(connman.ReceiveMsgFrom(
            peer, NetMsg::Make(NetMsgType::HEADERS, TX_WITH_WITNESS(headers))));
        peer.fPauseSend = false;
        (void)connman.ProcessMessagesOnce(peer);
        BOOST_CHECK(peerman.SendMessages(&peer));
        connman.FlushSendBuffer(peer);
        BOOST_REQUIRE(connman.ReceiveMsgFrom(
            peer, NetMsg::Make(NetMsgType::BLOCK, TX_WITH_WITNESS(child))));
        peer.fPauseSend = false;
        (void)connman.ProcessMessagesOnce(peer);

        BOOST_REQUIRE(PeermanWaitFor([&] {
            LOCK(::cs_main);
            const CBlockIndex* idx{
                m_node.chainman->m_blockman.LookupBlockIndex(child_hash)};
            return idx != nullptr &&
                   m_node.chainman->ActiveChain().Contains(idx);
        }));

        child_index = WITH_LOCK(::cs_main, {
            return m_node.chainman->m_blockman.LookupBlockIndex(child_hash);
        });
        BOOST_REQUIRE(child_index != nullptr);
        BlockValidationState invalidate_state;
        BOOST_REQUIRE(m_node.chainman->ActiveChainstate().InvalidateBlock(
            invalidate_state, child_index));
        {
            LOCK(::cs_main);
            m_node.chainman->ActiveChainstate().ResetBlockFailureFlags(child_index);
            BOOST_REQUIRE(child_index->nStatus & BLOCK_HAVE_DATA);
            BOOST_REQUIRE_EQUAL(child_index->nStatus & BLOCK_FAILED_MASK, 0);
            BOOST_REQUIRE(!m_node.chainman->ActiveChain().Contains(child_index));
            m_node.chainman->SetBestHeader(child_index);
        }
    }

    // 15s followed-child replay cooldown is unix mock time. Do not hold
    // g_msgproc_mutex: RetryMatMulDeferredBodies asserts it is absent.
    SetMockTime(std::chrono::seconds{
        WITH_LOCK(::cs_main, return m_node.chainman->ActiveTip()->GetBlockTime()) +
        120});
    peerman.RetryMatMulDeferredBodiesForTest();
    m_node.validation_signals->SyncWithValidationInterfaceQueue();

    BOOST_CHECK(WITH_LOCK(::cs_main, {
        return m_node.chainman->ActiveChain().Contains(child_index);
    }));
    {
        LOCK(::cs_main);
        m_node.chainman->SetBestHeader(
            const_cast<CBlockIndex*>(m_node.chainman->ActiveTip()));
    }
}

// Running stall 5301685574: a hash recorded as HEADER_ONLY competing must
// still be getdata'd once it is the followed tip-child. Skip sets used to
// clear only on ActiveTipChange (`root_header_only_skip`). Populate the
// skip set as a trusted mirror (signer-free CONSENSUS ExactReplays every
// tip-child), then switch role.
BOOST_AUTO_TEST_CASE(signer_free_consensus_getdata_followed_child_despite_header_only_skip)
{
    LOCK(NetEventsInterface::g_msgproc_mutex);

    node::matmul_trusted::ResetForTest();
    ResetSharedPeermanFixture(m_node);
    CKey signer;
    signer.MakeNewKey(/*fCompressed=*/true);
    matmul::trusted::StoreConfig mirror_config;
    mirror_config.chain_id = uint256::FromHex(std::string(64, '1')).value();
    mirror_config.replay_authority_context =
        uint256::FromHex(std::string(64, '2')).value();
    mirror_config.trusted_signers = {signer.GetPubKey()};
    mirror_config.threshold = 1;
    std::string error;
    BOOST_REQUIRE(node::matmul_trusted::Configure(
        std::move(mirror_config), /*trusted_mirror=*/true, /*serve=*/false,
        std::chrono::milliseconds{50}, error));
    BOOST_REQUIRE(node::matmul_trusted::IsTrustedMirror());
    struct VerifierReset {
        ~VerifierReset() { node::matmul_trusted::ResetForTest(); }
    } verifier_reset;

    auto& mode = const_cast<kernel::MatMulValidationMode&>(
        m_node.chainman->m_options.matmul_validation_mode);
    const auto saved_mode{mode};
    struct RestoreMode {
        kernel::MatMulValidationMode& mode;
        kernel::MatMulValidationMode saved;
        ~RestoreMode() { mode = saved; }
    } restore_mode{mode, saved_mode};

    ConnmanTestMsg& connman = static_cast<ConnmanTestMsg&>(*m_node.connman);
    PeerManager& peerman = *m_node.peerman;
    Consensus::Params& consensus = const_cast<Consensus::Params&>(
        m_node.chainman->GetParams().GetConsensus());
    auto restore_heights{SaveMatMulHeights(consensus)};

    const CBlockIndex* tip{
        WITH_LOCK(::cs_main, return m_node.chainman->ActiveChain().Tip())};
    BOOST_REQUIRE(tip != nullptr);
    SetMockTime(std::chrono::seconds{tip->GetBlockTime() + 1});
    ActivateRcAtTip(consensus, *tip);
    peerman.SetBestBlock(tip->nHeight, std::chrono::seconds{tip->GetBlockTime()});

    CBlock decoy{MineTipChild(m_node, *tip, /*extra_time=*/0)};
    CBlock followed{MineTipChild(m_node, *tip, /*extra_time=*/1)};
    BOOST_REQUIRE(decoy.GetHash() != followed.GetHash());
    const uint256 followed_hash{followed.GetHash()};

    const ServiceFlags services{ServiceFlags(
        NODE_NETWORK | NODE_WITNESS | NODE_MATMUL_CONSENSUS |
        NODE_MATMUL_ATTESTATION_ARCHIVE)};
    CNode peer{/*id=*/209,
               /*sock=*/nullptr,
               CAddress{PeermanTestService(0x0900007f), NODE_NETWORK},
               /*nKeyedNetGroupIn=*/0x69,
               /*nLocalHostNonceIn=*/0,
               CAddress{},
               /*addrNameIn=*/"signer-free-header-only-skip",
               ConnectionType::OUTBOUND_FULL_RELAY,
               /*inbound_onion=*/false,
               /*network_key=*/0};
    connman.Handshake(peer, /*successfully_connected=*/true, services, services,
                      PROTOCOL_VERSION, /*relay_txs=*/true);
    connman.AddTestNode(peer);
    connman.FlushSendBuffer(peer);
    struct FinalizePeer {
        ConnmanTestMsg& connman;
        PeerManager& peerman;
        CNode& node;
        ~FinalizePeer()
        {
            peerman.FinalizeNode(node);
            connman.RemoveTestNode(node);
        }
    } finalize{connman, peerman, peer};

    auto send_block = [&](const CBlock& block) {
        std::vector<CBlock> headers{CBlock{block.GetBlockHeader()}};
        BOOST_REQUIRE(connman.ReceiveMsgFrom(
            peer, NetMsg::Make(NetMsgType::HEADERS, TX_WITH_WITNESS(headers))));
        peer.fPauseSend = false;
        (void)connman.ProcessMessagesOnce(peer);
        connman.FlushSendBuffer(peer);
        BOOST_REQUIRE(connman.ReceiveMsgFrom(
            peer, NetMsg::Make(NetMsgType::BLOCK, TX_WITH_WITNESS(block))));
        peer.fPauseSend = false;
        (void)connman.ProcessMessagesOnce(peer);
    };
    send_block(decoy);
    send_block(followed);
    BOOST_CHECK(!peer.fDisconnect);
    CBlockIndex* decoy_index{WITH_LOCK(::cs_main, {
        return m_node.chainman->m_blockman.LookupBlockIndex(decoy.GetHash());
    })};
    CBlockIndex* followed_index{WITH_LOCK(::cs_main, {
        return m_node.chainman->m_blockman.LookupBlockIndex(followed_hash);
    })};
    BOOST_REQUIRE(decoy_index != nullptr);
    BOOST_REQUIRE(followed_index != nullptr);
    BOOST_CHECK_EQUAL(followed_index->nStatus & BLOCK_HAVE_DATA, 0);
    // CONSENSUS+mirror connects the first child, so the skipped sibling is
    // no longer a tip-child. Disconnect the decoy so the skipped hash is
    // again the followed tip-child of the original tip.
    if (WITH_LOCK(::cs_main, return m_node.chainman->ActiveChain().Contains(decoy_index))) {
        BlockValidationState invalidate_state;
        BOOST_REQUIRE(m_node.chainman->ActiveChainstate().InvalidateBlock(
            invalidate_state, decoy_index));
        LOCK(::cs_main);
        m_node.chainman->ActiveChainstate().ResetBlockFailureFlags(decoy_index);
    }
    BOOST_CHECK_EQUAL(
        WITH_LOCK(::cs_main, return m_node.chainman->ActiveTip()),
        tip);
    BOOST_CHECK_EQUAL(followed_index->nStatus & BLOCK_HAVE_DATA, 0);

    node::matmul_trusted::ResetForTest();
    matmul::trusted::StoreConfig verifier_config;
    verifier_config.chain_id = uint256::FromHex(std::string(64, '1')).value();
    verifier_config.replay_authority_context =
        uint256::FromHex(std::string(64, '2')).value();
    verifier_config.trusted_signers = {signer.GetPubKey()};
    verifier_config.threshold = 1;
    BOOST_REQUIRE(node::matmul_trusted::Configure(
        std::move(verifier_config), /*trusted_mirror=*/false, /*serve=*/false,
        std::chrono::milliseconds{50}, error));
    mode = kernel::MatMulValidationMode::CONSENSUS;
    BOOST_REQUIRE(!node::matmul_trusted::HasLocalSigner());
    BOOST_REQUIRE(!node::matmul_trusted::IsTrustedMirror());
    {
        LOCK(::cs_main);
        m_node.chainman->SetBestHeader(followed_index);
        BOOST_CHECK(m_node.chainman->IndexIsFollowedTipChild(
            m_node.chainman->ActiveTip(), followed_index));
    }

    CNode source{/*id=*/210,
                 /*sock=*/nullptr,
                 CAddress{PeermanTestService(0x0a00007f), NODE_NETWORK},
                 /*nKeyedNetGroupIn=*/0x6a,
                 /*nLocalHostNonceIn=*/0,
                 CAddress{},
                 /*addrNameIn=*/"signer-free-followed-body-source",
                 ConnectionType::OUTBOUND_FULL_RELAY,
                 /*inbound_onion=*/false,
                 /*network_key=*/0};
    connman.Handshake(source, /*successfully_connected=*/true, services,
                      services, PROTOCOL_VERSION, /*relay_txs=*/true);
    connman.AddTestNode(source);
    connman.FlushSendBuffer(source);
    struct FinalizeSource {
        ConnmanTestMsg& connman;
        PeerManager& peerman;
        CNode& node;
        ~FinalizeSource()
        {
            peerman.FinalizeNode(node);
            connman.RemoveTestNode(node);
        }
    } finalize_source{connman, peerman, source};

    std::vector<CBlock> followed_headers{CBlock{followed.GetBlockHeader()}};
    BOOST_REQUIRE(connman.ReceiveMsgFrom(
        source, NetMsg::Make(NetMsgType::HEADERS,
                             TX_WITH_WITNESS(followed_headers))));
    source.fPauseSend = false;
    (void)connman.ProcessMessagesOnce(source);

    bool fetched{false};
    for (int i = 0; i < 10; ++i) {
        BOOST_CHECK(peerman.SendMessages(&source));
        if (CountQueuedGetDataForHash(source, followed_hash) > 0 ||
            HasQueuedMessageType(source, NetMsgType::GETDATA)) {
            fetched = true;
            break;
        }
        CNodeStateStats source_stats;
        BOOST_REQUIRE(peerman.GetNodeStateStats(source.GetId(), source_stats));
        if (std::find(source_stats.vHeightInFlight.begin(),
                      source_stats.vHeightInFlight.end(),
                      tip->nHeight + 1) != source_stats.vHeightInFlight.end()) {
            fetched = true;
            break;
        }
        connman.FlushSendBuffer(source);
    }
    BOOST_CHECK(fetched);
    BOOST_CHECK(!source.fDisconnect);
}

BOOST_AUTO_TEST_CASE(authenticated_chain_progress_lane_does_not_pace_one_per_minute)
{
    LOCK(NetEventsInterface::g_msgproc_mutex);

    node::matmul_trusted::ResetForTest();
    ResetSharedPeermanFixture(m_node);
    ConnmanTestMsg& connman = static_cast<ConnmanTestMsg&>(*m_node.connman);
    PeerManager& peerman = *m_node.peerman;
    ResetGlobalMatMulRCBudgetForTest();

    const CBlockIndex* tip{
        WITH_LOCK(::cs_main, return m_node.chainman->ActiveChain().Tip())};
    BOOST_REQUIRE(tip != nullptr);
    SetMockTime(std::chrono::seconds{tip->GetBlockTime() + 1});
    peerman.SetBestBlock(tip->nHeight, std::chrono::seconds{tip->GetBlockTime()});

    Consensus::Params& consensus = const_cast<Consensus::Params&>(
        m_node.chainman->GetParams().GetConsensus());
    auto restore_heights{SaveMatMulHeights(consensus)};
    ActivateRcAtTip(consensus, *tip);
    // Production 1/min windows. Progress lane must still admit sequential
    // followed children. Do not raise the product defaults; this only
    // keeps the pending cap from hiding the rate-window behaviour.
    consensus.nMatMulRCGlobalVerifyBudgetPerMin = 1;
    consensus.nMatMulRCPeerVerifyBudgetPerMin = 1;
    consensus.nMatMulRCMaxPendingVerifications = 2;

    peerman.InstallMatMulVerifyOverrideForTest(
        [&](const CBlock&, int32_t, std::optional<int64_t>) { return true; });
    struct ClearOverride {
        PeerManager& peerman;
        ~ClearOverride() { peerman.InstallMatMulVerifyOverrideForTest({}); }
    } clear_override{peerman};

    const ServiceFlags services{ServiceFlags(NODE_NETWORK | NODE_WITNESS | NODE_MATMUL_CONSENSUS)};
    CNode occupier{/*id=*/203,
                   /*sock=*/nullptr,
                   CAddress{PeermanTestService(0x0300007f), NODE_NETWORK},
                   /*nKeyedNetGroupIn=*/0x33,
                   /*nLocalHostNonceIn=*/0,
                   CAddress{},
                   /*addrNameIn=*/"progress-lane-occupier",
                   ConnectionType::OUTBOUND_FULL_RELAY,
                   /*inbound_onion=*/false,
                   /*network_key=*/0};
    connman.Handshake(occupier, /*successfully_connected=*/true, services,
                      services, PROTOCOL_VERSION, /*relay_txs=*/true);
    connman.AddTestNode(occupier);
    connman.FlushSendBuffer(occupier);
    struct FinalizePeer {
        ConnmanTestMsg& connman;
        PeerManager& peerman;
        CNode& node;
        ~FinalizePeer()
        {
            peerman.FinalizeNode(node);
            connman.RemoveTestNode(node);
        }
    } finalize{connman, peerman, occupier};

    auto send_full = [&](CNode& node, const CBlock& block) {
        const auto ticket{GrindTicket(block.GetBlockHeader(), consensus.powLimit)};
        std::vector<CBlock> headers{CBlock{block.GetBlockHeader()}};
        connman.FlushSendBuffer(node);
        node.fPauseSend = false;
        BOOST_REQUIRE(connman.ReceiveMsgFrom(
            node, NetMsg::Make(NetMsgType::HEADERS, TX_WITH_WITNESS(headers))));
        node.fPauseSend = false;
        (void)connman.ProcessMessagesOnce(node);
        connman.FlushSendBuffer(node);
        BOOST_REQUIRE(connman.ReceiveMsgFrom(
            node, NetMsg::Make(NetMsgType::RCADMIT, ticket)));
        node.fPauseSend = false;
        (void)connman.ProcessMessagesOnce(node);
        connman.FlushSendBuffer(node);
        BOOST_REQUIRE(connman.ReceiveMsgFrom(
            node, NetMsg::Make(NetMsgType::BLOCK, TX_WITH_WITNESS(block))));
        node.fPauseSend = false;
        (void)connman.ProcessMessagesOnce(node);
        connman.FlushSendBuffer(node);
    };

    CBlock first{MineTipChild(m_node, *tip, /*extra_time=*/0)};
    send_full(occupier, first);
    const uint256 first_hash{first.GetHash()};
    BOOST_REQUIRE(PeermanWaitFor([&] {
        LOCK(::cs_main);
        const CBlockIndex* idx{
            m_node.chainman->m_blockman.LookupBlockIndex(first_hash)};
        return idx != nullptr && (idx->nStatus & BLOCK_HAVE_DATA) != 0;
    }));
    BOOST_CHECK(!peerman.HasMatMulRetainedBodyForTest(first_hash));
    for (int i = 0; i < 8; ++i) {
        (void)peerman.SendMessages(&occupier);
        m_node.validation_signals->SyncWithValidationInterfaceQueue();
        connman.FlushSendBuffer(occupier);
        if (WITH_LOCK(::cs_main, {
                const CBlockIndex* idx{
                    m_node.chainman->m_blockman.LookupBlockIndex(first_hash)};
                return idx != nullptr &&
                       m_node.chainman->ActiveChain().Contains(idx);
            })) {
            break;
        }
    }
    BOOST_REQUIRE(WITH_LOCK(::cs_main, {
        const CBlockIndex* idx{
            m_node.chainman->m_blockman.LookupBlockIndex(first_hash)};
        return idx != nullptr && m_node.chainman->ActiveChain().Contains(idx);
    }));

    const CBlockIndex* after_first{
        WITH_LOCK(::cs_main, return m_node.chainman->ActiveChain().Tip())};
    BOOST_REQUIRE(after_first != nullptr);
    CBlock second{MineTipChild(m_node, *after_first, /*extra_time=*/0)};
    send_full(occupier, second);
    const uint256 second_hash{second.GetHash()};
    BOOST_REQUIRE(PeermanWaitFor([&] {
        LOCK(::cs_main);
        const CBlockIndex* idx{
            m_node.chainman->m_blockman.LookupBlockIndex(second_hash)};
        return idx != nullptr && (idx->nStatus & BLOCK_HAVE_DATA) != 0;
    }));
    BOOST_CHECK_MESSAGE(
        !peerman.HasMatMulRetainedBodyForTest(second_hash),
        "second followed tip-child was 1/min-retained; progress lane missing");
    BOOST_CHECK(!occupier.fDisconnect);
}

BOOST_AUTO_TEST_CASE(duplicate_header_no_progress_flood_disconnects_inbound_peer)
{
    LOCK(NetEventsInterface::g_msgproc_mutex);

    node::matmul_trusted::ResetForTest();
    ResetSharedPeermanFixture(m_node);
    ConnmanTestMsg& connman = static_cast<ConnmanTestMsg&>(*m_node.connman);
    PeerManager& peerman = *m_node.peerman;

    const CBlockIndex* start_tip{
        WITH_LOCK(::cs_main, return m_node.chainman->ActiveChain().Tip())};
    BOOST_REQUIRE(start_tip != nullptr);
    for (int i = 0; i < 8; ++i) {
        mineBlock(m_node, std::chrono::seconds{start_tip->GetBlockTime() + 1 + i});
    }

    std::vector<CBlock> known;
    {
        LOCK(::cs_main);
        const CBlockIndex* walk{m_node.chainman->ActiveChain().Tip()};
        for (int i = 0; i < 8 && walk != nullptr; ++i) {
            known.emplace_back(walk->GetBlockHeader());
            walk = walk->pprev;
        }
    }
    std::reverse(known.begin(), known.end());
    BOOST_REQUIRE_EQUAL(known.size(), 8U);

    const ServiceFlags services{ServiceFlags(NODE_NETWORK | NODE_WITNESS)};
    CNode attacker{/*id=*/302,
                   /*sock=*/nullptr,
                   CAddress{PeermanTestService(0x0c00007f), NODE_NETWORK},
                   /*nKeyedNetGroupIn=*/0x0c,
                   /*nLocalHostNonceIn=*/0,
                   CAddress{},
                   /*addrNameIn=*/"dup-header-flood",
                   ConnectionType::INBOUND,
                   /*inbound_onion=*/false,
                   /*network_key=*/0};
    connman.Handshake(attacker, /*successfully_connected=*/true, services,
                      services, PROTOCOL_VERSION, /*relay_txs=*/true);
    connman.AddTestNode(attacker);
    connman.FlushSendBuffer(attacker);
    struct FinalizeAttacker {
        ConnmanTestMsg& connman;
        PeerManager& peerman;
        CNode& node;
        ~FinalizeAttacker()
        {
            peerman.FinalizeNode(node);
            connman.RemoveTestNode(node);
        }
    } finalize{connman, peerman, attacker};

    // Handshake getheaders marks the first replay solicited. Subsequent
    // unsolicited 8-header ancestor batches must disconnect after 8 counted
    // messages; send extra so the solicited opener cannot starve the window.
    for (int i = 0; i < 16; ++i) {
        attacker.fPauseSend = false;
        connman.FlushSendBuffer(attacker);
        BOOST_REQUIRE(connman.ReceiveMsgFrom(
            attacker, NetMsg::Make(NetMsgType::HEADERS, TX_WITH_WITNESS(known))));
        attacker.fPauseSend = false;
        (void)connman.ProcessMessagesOnce(attacker);
        if (attacker.fDisconnect) break;
    }
    BOOST_CHECK(attacker.fDisconnect);
    CNodeStateStats stats;
    BOOST_REQUIRE(peerman.GetNodeStateStats(attacker.GetId(), stats));
    BOOST_CHECK_EQUAL(stats.m_dup_header_action, "disconnected");
}

// Live 2026-08-15: GETMMATTEST for the unique attested tip-child returned
// not_validated while ExactReplay/connect was in flight, then rate_limited
// (height=-1) 2s after UpdateTip because those probes charged the 16-token
// bucket. Observers polling the headers-only front never received MMATTEST.
BOOST_AUTO_TEST_CASE(getmmattest_not_validated_does_not_starve_canonical_serve)
{
    LOCK(NetEventsInterface::g_msgproc_mutex);

    node::matmul_trusted::ResetForTest();
    ResetSharedPeermanFixture(m_node);
    CKey signer;
    signer.MakeNewKey(/*fCompressed=*/true);
    matmul::trusted::StoreConfig config;
    config.chain_id = uint256::FromHex(std::string(64, '1')).value();
    config.replay_authority_context =
        uint256::FromHex(std::string(64, '2')).value();
    config.trusted_signers = {signer.GetPubKey()};
    config.threshold = 1;
    config.local_signer = signer;
    std::string error;
    BOOST_REQUIRE(node::matmul_trusted::Configure(
        std::move(config), /*trusted_mirror=*/false, /*serve=*/true,
        std::chrono::milliseconds{50}, error));
    BOOST_REQUIRE(node::matmul_trusted::HasLocalSigner());
    BOOST_REQUIRE(node::matmul_trusted::ServesAttestations());
    struct SignerReset {
        ~SignerReset() { node::matmul_trusted::ResetForTest(); }
    } signer_reset;

    ConnmanTestMsg& connman = static_cast<ConnmanTestMsg&>(*m_node.connman);
    PeerManager& peerman = *m_node.peerman;

    Consensus::Params& consensus = const_cast<Consensus::Params&>(
        m_node.chainman->GetParams().GetConsensus());
    auto restore_heights{SaveMatMulHeights(consensus)};

    const CBlockIndex* tip{
        WITH_LOCK(::cs_main, return m_node.chainman->ActiveChain().Tip())};
    BOOST_REQUIRE(tip != nullptr);
    SetMockTime(std::chrono::seconds{tip->GetBlockTime() + 1});
    ActivateRcAtTip(consensus, *tip);
    peerman.SetBestBlock(tip->nHeight, std::chrono::seconds{tip->GetBlockTime()});
    BOOST_REQUIRE(consensus.IsMatMulTrustedReplayAttestationActive(tip->nHeight));
    BOOST_REQUIRE(
        consensus.IsMatMulTrustedReplayAttestationActive(tip->nHeight + 1));

    const uint256 tip_hash{tip->GetBlockHash()};
    const int32_t tip_height{tip->nHeight};
    BOOST_REQUIRE(node::matmul_trusted::SignAuthoritative(tip_hash, tip_height) ==
                  matmul::trusted::AddResult::Accepted);
    BOOST_REQUIRE(node::matmul_trusted::HasQuorum(tip_hash, tip_height));

    CBlock child{MineTipChild(m_node, *tip, /*extra_time=*/0)};
    const uint256 child_hash{child.GetHash()};
    std::vector<CBlock> child_headers{CBlock{child.GetBlockHeader()}};

    const ServiceFlags services{ServiceFlags(
        NODE_NETWORK | NODE_WITNESS | NODE_MATMUL_CONSENSUS)};
    CNode observer{/*id=*/401,
                   /*sock=*/nullptr,
                   CAddress{PeermanTestService(0x0d00007f), NODE_NETWORK},
                   /*nKeyedNetGroupIn=*/0x0d,
                   /*nLocalHostNonceIn=*/0,
                   CAddress{},
                   /*addrNameIn=*/"mmattest-observer",
                   ConnectionType::INBOUND,
                   /*inbound_onion=*/false,
                   /*network_key=*/0};
    connman.Handshake(observer, /*successfully_connected=*/true, services,
                      services, PROTOCOL_VERSION, /*relay_txs=*/true);
    connman.AddTestNode(observer);
    connman.FlushSendBuffer(observer);
    struct FinalizeObserver {
        ConnmanTestMsg& connman;
        PeerManager& peerman;
        CNode& node;
        ~FinalizeObserver()
        {
            peerman.FinalizeNode(node);
            connman.RemoveTestNode(node);
        }
    } finalize{connman, peerman, observer};

    BOOST_REQUIRE(connman.ReceiveMsgFrom(
        observer, NetMsg::Make(NetMsgType::HEADERS, TX_WITH_WITNESS(child_headers))));
    observer.fPauseSend = false;
    (void)connman.ProcessMessagesOnce(observer);
    connman.FlushSendBuffer(observer);

    {
        LOCK(::cs_main);
        const CBlockIndex* child_index{
            m_node.chainman->m_blockman.LookupBlockIndex(child_hash)};
        BOOST_REQUIRE(child_index != nullptr);
        BOOST_CHECK_EQUAL(child_index->nStatus & BLOCK_HAVE_DATA, 0);
        BOOST_CHECK(!m_node.chainman->ActiveChain().Contains(child_index));
    }

    // More probes than the 16-token burst. Frozen mock time ⇒ no refill.
    for (int i = 0; i < 20; ++i) {
        observer.fPauseSend = false;
        BOOST_REQUIRE(connman.ReceiveMsgFrom(
            observer, NetMsg::Make(NetMsgType::GETMMATTEST, child_hash)));
        observer.fPauseSend = false;
        (void)connman.ProcessMessagesOnce(observer);
        BOOST_CHECK(!HasQueuedMessageType(observer, NetMsgType::MMATTEST));
        connman.FlushSendBuffer(observer);
    }

    observer.fPauseSend = false;
    BOOST_REQUIRE(connman.ReceiveMsgFrom(
        observer, NetMsg::Make(NetMsgType::GETMMATTEST, tip_hash)));
    observer.fPauseSend = false;
    (void)connman.ProcessMessagesOnce(observer);
    BOOST_CHECK(HasQueuedMessageType(observer, NetMsgType::MMATTEST));
}

// Lost twin race with both bodies already HAVE_DATA: FindLowestMissingBody
// is nullptr, so the scheduler used to skip GETMMATTEST for the competing
// sibling. recovery_escape needs the local quorum record; without this
// request the attested twin waits for +2 work while miners keep extending
// the loser. Network-wide (extra twins, HEADER_ONLY skips), not a GBT
// concession. Does not weaken hysteresis for unattested equal-work races.
BOOST_AUTO_TEST_CASE(getmmattest_lost_twin_complete_bodies_requests_fork_child)
{
    LOCK(NetEventsInterface::g_msgproc_mutex);

    node::matmul_trusted::ResetForTest();
    ResetSharedPeermanFixture(m_node);
    CKey signer;
    signer.MakeNewKey(/*fCompressed=*/true);
    matmul::trusted::StoreConfig config;
    config.chain_id = uint256::FromHex(std::string(64, '1')).value();
    config.replay_authority_context =
        uint256::FromHex(std::string(64, '2')).value();
    config.trusted_signers = {signer.GetPubKey()};
    config.threshold = 1;
    std::string error;
    BOOST_REQUIRE(node::matmul_trusted::Configure(
        std::move(config), /*trusted_mirror=*/false, /*serve=*/false,
        std::chrono::milliseconds{50}, error));
    BOOST_REQUIRE(!node::matmul_trusted::IsTrustedMirror());
    BOOST_REQUIRE(node::matmul_trusted::IsConfigured());
    BOOST_REQUIRE(!node::matmul_trusted::HasLocalSigner());
    struct VerifierReset {
        ~VerifierReset() { node::matmul_trusted::ResetForTest(); }
    } verifier_reset;

    auto& mode = const_cast<kernel::MatMulValidationMode&>(
        m_node.chainman->m_options.matmul_validation_mode);
    const auto saved_mode{mode};
    struct RestoreMode {
        kernel::MatMulValidationMode& mode;
        kernel::MatMulValidationMode saved;
        ~RestoreMode() { mode = saved; }
    } restore_mode{mode, saved_mode};
    mode = kernel::MatMulValidationMode::CONSENSUS;

    ConnmanTestMsg& connman = static_cast<ConnmanTestMsg&>(*m_node.connman);
    PeerManager& peerman = *m_node.peerman;
    peerman.InstallMatMulVerifyOverrideForTest(
        [&](const CBlock&, int32_t, std::optional<int64_t>) { return true; });
    struct ClearOverride {
        PeerManager& peerman;
        ~ClearOverride() { peerman.InstallMatMulVerifyOverrideForTest({}); }
    } clear_override{peerman};

    Consensus::Params& consensus = const_cast<Consensus::Params&>(
        m_node.chainman->GetParams().GetConsensus());
    auto restore_heights{SaveMatMulHeights(consensus)};

    const CBlockIndex* parent{
        WITH_LOCK(::cs_main, return m_node.chainman->ActiveChain().Tip())};
    BOOST_REQUIRE(parent != nullptr);
    SetMockTime(std::chrono::seconds{parent->GetBlockTime() + 1});
    ActivateRcAtTip(consensus, *parent);
    peerman.SetBestBlock(parent->nHeight,
                         std::chrono::seconds{parent->GetBlockTime()});
    BOOST_REQUIRE(
        consensus.IsMatMulTrustedReplayAttestationActive(parent->nHeight + 1));

    CBlock ours{MineTipChild(m_node, *parent, /*extra_time=*/0)};
    CBlock competing{MineTipChild(m_node, *parent, /*extra_time=*/1)};
    BOOST_REQUIRE(ours.GetHash() != competing.GetHash());
    const uint256 competing_hash{competing.GetHash()};

    BOOST_REQUIRE(m_node.chainman->ProcessNewBlock(
        std::make_shared<const CBlock>(ours), /*force_processing=*/true,
        /*min_pow_checked=*/true, nullptr));
    BOOST_REQUIRE(m_node.chainman->ProcessNewBlock(
        std::make_shared<const CBlock>(competing), /*force_processing=*/true,
        /*min_pow_checked=*/true, nullptr));
    m_node.validation_signals->SyncWithValidationInterfaceQueue();

    {
        LOCK(::cs_main);
        const CBlockIndex* tip{m_node.chainman->ActiveChain().Tip()};
        BOOST_REQUIRE(tip != nullptr);
        BOOST_CHECK_EQUAL(tip->GetBlockHash(), ours.GetHash());
        const CBlockIndex* competing_index{
            m_node.chainman->m_blockman.LookupBlockIndex(competing_hash)};
        BOOST_REQUIRE(competing_index != nullptr);
        BOOST_CHECK(competing_index->nStatus & BLOCK_HAVE_DATA);
        BOOST_CHECK(!m_node.chainman->ActiveChain().Contains(competing_index));
        BOOST_CHECK(!node::matmul_trusted::HasQuorum(
            competing_hash, competing_index->nHeight));
    }

    const ServiceFlags archive_services{ServiceFlags(
        NODE_NETWORK | NODE_WITNESS | NODE_MATMUL_CONSENSUS |
        NODE_MATMUL_ATTESTATION_ARCHIVE)};
    CNode archive{/*id=*/402,
                  /*sock=*/nullptr,
                  CAddress{PeermanTestService(0x0e00007f), NODE_NETWORK},
                  /*nKeyedNetGroupIn=*/0x0e,
                  /*nLocalHostNonceIn=*/0,
                  CAddress{},
                  /*addrNameIn=*/"lost-twin-archive",
                  ConnectionType::OUTBOUND_FULL_RELAY,
                  /*inbound_onion=*/false,
                  /*network_key=*/0};
    connman.Handshake(archive, /*successfully_connected=*/true,
                      archive_services, archive_services, PROTOCOL_VERSION,
                      /*relay_txs=*/true);
    connman.AddTestNode(archive);
    connman.FlushSendBuffer(archive);
    struct FinalizeArchive {
        ConnmanTestMsg& connman;
        PeerManager& peerman;
        CNode& node;
        ~FinalizeArchive()
        {
            peerman.FinalizeNode(node);
            connman.RemoveTestNode(node);
        }
    } finalize{connman, peerman, archive};

    std::vector<CBlock> competing_headers{CBlock{competing.GetBlockHeader()}};
    BOOST_REQUIRE(connman.ReceiveMsgFrom(
        archive,
        NetMsg::Make(NetMsgType::HEADERS, TX_WITH_WITNESS(competing_headers))));
    archive.fPauseSend = false;
    (void)connman.ProcessMessagesOnce(archive);
    connman.FlushSendBuffer(archive);

    BOOST_CHECK(peerman.SendMessages(&archive));
    BOOST_CHECK_GE(CountQueuedGetMmAttestForHash(archive, competing_hash), 1);
}

BOOST_AUTO_TEST_SUITE_END()
