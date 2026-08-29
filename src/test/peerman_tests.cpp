// Copyright (c) 2024-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://www.opensource.org/licenses/mit-license.php.

#include <banman.h>
#include <blockencodings.h>
#include <chainparams.h>
#include <consensus/merkle.h>
#include <key.h>
#include <matmul/trusted_exact_replay_attestation.h>
#include <net_types.h>
#include <netbase.h>
#include <node/matmul_rc_admission.h>
#include <node/matmul_trusted_attestations.h>
#include <node/block_chunk_transport.h>
#include <node/miner.h>
#include <node/transaction.h>
#include <net_processing.h>
#include <node/kernel_notifications.h>
#include <node/header_sync.h>
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
#include <memory>
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

static size_t CountQueuedMessageType(CNode& node, const std::string& msg_type)
{
    LOCK(node.cs_vSend);
    if (node.vSendMsg.empty()) {
        const auto& [bytes, _more, transport_type] =
            node.m_transport->GetBytesToSend(false);
        return (!bytes.empty() && transport_type == msg_type) ? 1 : 0;
    }
    return static_cast<size_t>(std::count_if(
        node.vSendMsg.begin(), node.vSendMsg.end(),
        [&](const CSerializedNetMsg& msg) { return msg.m_type == msg_type; }));
}

// HEADERS wire is compact-size count + each 80-byte header + vtx count 0.
// Same parse as PeerManager::ProcessMessage(HEADERS). Do not deserialize as
// vector<CBlock>: that is not the receive path, and a throw looks like
// "served zero headers" even when the bytes are on the wire.
static size_t CountHeadersInPayload(Span<const uint8_t> payload)
{
    if (payload.empty()) return 0;
    DataStream stream{payload};
    try {
        const uint64_t n_count{ReadCompactSize(stream)};
        for (uint64_t i = 0; i < n_count; ++i) {
            CBlockHeader header;
            stream >> header;
            if (ReadCompactSize(stream) != 0) return 0;
        }
        return static_cast<size_t>(n_count);
    } catch (const std::ios_base::failure&) {
        return 0;
    }
}

static size_t CountQueuedHeaderBlocks(CNode& node)
{
    LOCK(node.cs_vSend);
    size_t n{0};
    for (const auto& msg : node.vSendMsg) {
        if (msg.m_type != NetMsgType::HEADERS) continue;
        n += CountHeadersInPayload(msg.data);
    }
    if (n > 0) return n;

    // sock=null tests: PushMessage optimistic-write moves the message into
    // V1Transport and erases vSendMsg. GetBytesToSend is the 24-byte V1
    // header until MarkBytesSent; empty HEADERS is nMessageSize == 1.
    const auto& [bytes, _more, transport_type] =
        node.m_transport->GetBytesToSend(false);
    if (bytes.empty() || transport_type != NetMsgType::HEADERS) return n;
    if (bytes.size() == CMessageHeader::HEADER_SIZE) {
        DataStream hdr_stream{bytes};
        try {
            CMessageHeader hdr;
            hdr_stream >> hdr;
            if (hdr.nMessageSize <= 1) return 0;
            if (hdr.nMessageSize >= 3 && (hdr.nMessageSize - 3) % 81 == 0 &&
                (hdr.nMessageSize - 3) / 81 >= 253) {
                return (hdr.nMessageSize - 3) / 81;
            }
            if ((hdr.nMessageSize - 1) % 81 == 0) {
                return (hdr.nMessageSize - 1) / 81;
            }
            return 1;
        } catch (const std::ios_base::failure&) {
            return 0;
        }
    }
    return CountHeadersInPayload(bytes);
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
    chainman.m_best_claimed_header = tip;
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
// displace that frontier (archive-A: headers==blocks frozen while competing
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
    // Outbound sibling archive/mirror: trusted mirrors drop HEADERS/BLOCK
    // from ordinary miners (GPU or our outbound ARCHIVE/MIRROR only).
    const ServiceFlags ordinary_services{ServiceFlags(
        NODE_NETWORK | NODE_WITNESS | NODE_MATMUL_CONSENSUS |
        NODE_MATMUL_ATTESTATION_ARCHIVE | NODE_MATMUL_TRUSTED_MIRROR)};

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

    // Spacing-formula deadline is 90s*(1+0.5*others), not a flat 15s.
    // Two download peers → 135s. Jump past that plus the 15s expire cooldown.
    SetMockTime(std::chrono::seconds{GetTime() + 136});
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

BOOST_AUTO_TEST_CASE(catchup_later_peer_fetches_next_window_segment)
{
    // FindNextBlocks used to return at the first in-flight root, so every
    // peer after the first two duplicated the same 16 hashes. CONTINUE lets
    // peer 4 take tip+17 once three owners hold the lowest segment.
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
    constexpr int kHeaders = 48;
    for (int i = 0; i < kHeaders; ++i) {
        CBlockIndex* nxt{make_header(*walk, 0xf00u + static_cast<unsigned int>(i))};
        headers.push_back(nxt);
        walk = nxt;
    }

    const ServiceFlags services{ServiceFlags(NODE_NETWORK | NODE_WITNESS)};
    CNode p1{/*id=*/201, /*sock=*/nullptr, CAddress{},
             /*nKeyedNetGroupIn=*/201, /*nLocalHostNonceIn=*/0,
             CAddress{}, /*addrNameIn=*/"seg-p1",
             ConnectionType::OUTBOUND_FULL_RELAY,
             /*inbound_onion=*/false, /*network_key=*/0};
    CNode p2{/*id=*/202, /*sock=*/nullptr, CAddress{},
             /*nKeyedNetGroupIn=*/202, /*nLocalHostNonceIn=*/0,
             CAddress{}, /*addrNameIn=*/"seg-p2",
             ConnectionType::OUTBOUND_FULL_RELAY,
             /*inbound_onion=*/false, /*network_key=*/0};
    CNode p3{/*id=*/203, /*sock=*/nullptr, CAddress{},
             /*nKeyedNetGroupIn=*/203, /*nLocalHostNonceIn=*/0,
             CAddress{}, /*addrNameIn=*/"seg-p3",
             ConnectionType::OUTBOUND_FULL_RELAY,
             /*inbound_onion=*/false, /*network_key=*/0};
    CNode p4{/*id=*/204, /*sock=*/nullptr, CAddress{},
             /*nKeyedNetGroupIn=*/204, /*nLocalHostNonceIn=*/0,
             CAddress{}, /*addrNameIn=*/"seg-p4",
             ConnectionType::OUTBOUND_FULL_RELAY,
             /*inbound_onion=*/false, /*network_key=*/0};
    connman.Handshake(p1, true, services, services, PROTOCOL_VERSION, true);
    connman.Handshake(p2, true, services, services, PROTOCOL_VERSION, true);
    connman.Handshake(p3, true, services, services, PROTOCOL_VERSION, true);
    connman.Handshake(p4, true, services, services, PROTOCOL_VERSION, true);
    connman.FlushSendBuffer(p1);
    connman.FlushSendBuffer(p2);
    connman.FlushSendBuffer(p3);
    connman.FlushSendBuffer(p4);
    p1.fPauseSend = false;
    p2.fPauseSend = false;
    p3.fPauseSend = false;
    p4.fPauseSend = false;
    struct FinalizeSeg {
        PeerManager& peerman;
        ConnmanTestMsg& connman;
        CNode& a;
        CNode& b;
        CNode& c;
        CNode& d;
        ~FinalizeSeg()
        {
            peerman.FinalizeNode(a);
            peerman.FinalizeNode(b);
            peerman.FinalizeNode(c);
            peerman.FinalizeNode(d);
            connman.RemoveTestNode(a);
            connman.RemoveTestNode(b);
            connman.RemoveTestNode(c);
            connman.RemoveTestNode(d);
        }
    } finalize{peerman, connman, p1, p2, p3, p4};

    std::vector<CBlock> hdrs;
    hdrs.reserve(headers.size());
    {
        LOCK(::cs_main);
        for (CBlockIndex* idx : headers) {
            hdrs.emplace_back(idx->GetBlockHeader());
        }
    }
    for (CNode* n : {&p1, &p2, &p3, &p4}) {
        BOOST_REQUIRE(connman.ReceiveMsgFrom(
            *n, NetMsg::Make(NetMsgType::HEADERS, TX_WITH_WITNESS(hdrs))));
        n->fPauseSend = false;
        (void)connman.ProcessMessagesOnce(*n);
    }

    BOOST_CHECK(peerman.SendMessages(&p1));
    BOOST_CHECK(peerman.SendMessages(&p2));
    BOOST_CHECK(peerman.SendMessages(&p3));
    BOOST_CHECK(peerman.SendMessages(&p4));
    CNodeStateStats s1, s4;
    BOOST_REQUIRE(peerman.GetNodeStateStats(p1.GetId(), s1));
    BOOST_REQUIRE(peerman.GetNodeStateStats(p4.GetId(), s4));
    BOOST_REQUIRE(!s1.vHeightInFlight.empty());
    BOOST_CHECK_EQUAL(s1.vHeightInFlight.front(), tip->nHeight + 1);
    BOOST_REQUIRE_MESSAGE(
        !s4.vHeightInFlight.empty(),
        "fourth peer must receive unique GETDATA after three owners hold the root segment");
    BOOST_CHECK_GT(s4.vHeightInFlight.front(), tip->nHeight + 16);
    NeutralizeUnconnectedHeaders(chainman);
    peerman.ResetMatMulVerifyAdmissionForTest();
}

// Live 2026-08-16: trusted-mirror archives 34–59 behind the signed frontier
// filled 16 getdatas from CONSENSUS miners (HEADER_ONLY gossip), timed out
// at 15s, and disconnected the only download peer. Prefer the archive peer
// and keep the 1-wide window even when ahead ≥ 32.
BOOST_AUTO_TEST_CASE(signed_frontier_catchup_prefers_archive_not_miner)
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
        std::move(config), /*trusted_mirror=*/true, /*serve=*/false,
        std::chrono::milliseconds{50}, error));
    BOOST_REQUIRE(node::matmul_trusted::IsTrustedMirror());
    struct MirrorReset {
        ~MirrorReset() { node::matmul_trusted::ResetForTest(); }
    } mirror_reset;

    ChainstateManager& chainman{*Assert(m_node.chainman)};
    PeerManager& peerman{*Assert(m_node.peerman)};
    ConnmanTestMsg& connman{static_cast<ConnmanTestMsg&>(*m_node.connman)};
    const CBlockIndex* starting_tip{
        WITH_LOCK(::cs_main, return chainman.ActiveChain().Tip())};
    BOOST_REQUIRE(starting_tip != nullptr);
    SetMockTime(std::chrono::seconds{starting_tip->GetBlockTime() + 3600});
    BOOST_REQUIRE(!chainman.IsInitialBlockDownload());

    const uint256 tip_hash{starting_tip->GetBlockHash()};
    const int32_t tip_height{starting_tip->nHeight};
    BOOST_REQUIRE(node::matmul_trusted::SignAuthoritative(tip_hash, tip_height) ==
                  matmul::trusted::AddResult::Accepted);

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
    constexpr int kAhead = 33;
    for (int i = 0; i < kAhead; ++i) {
        CBlockIndex* nxt{make_header(*walk, 0xf00u + static_cast<unsigned int>(i))};
        headers.push_back(nxt);
        walk = nxt;
    }
    BOOST_REQUIRE_EQUAL(headers.size(), static_cast<size_t>(kAhead));
    node::matmul_trusted::NoteAcceptedAttestationHeight(
        headers.back()->nHeight, headers.back()->GetBlockHash());
    {
        LOCK(::cs_main);
        const auto frontier{chainman.GetSignedFrontierStatus()};
        BOOST_REQUIRE(frontier.available);
        BOOST_CHECK_GE(frontier.blocks_behind, 2);
        BOOST_CHECK_EQUAL(
            chainman.m_best_header->nHeight, tip->nHeight + kAhead);
    }

    const ServiceFlags miner_services{ServiceFlags(
        NODE_NETWORK | NODE_WITNESS | NODE_MATMUL_CONSENSUS)};
    const ServiceFlags archive_services{ServiceFlags(
        NODE_NETWORK | NODE_WITNESS | NODE_MATMUL_ATTESTATION_ARCHIVE |
        NODE_MATMUL_TRUSTED_MIRROR)};
    CNode miner{/*id=*/196, /*sock=*/nullptr, CAddress{},
                /*nKeyedNetGroupIn=*/0, /*nLocalHostNonceIn=*/0,
                CAddress{}, /*addrNameIn=*/"frontier-miner",
                ConnectionType::OUTBOUND_FULL_RELAY,
                /*inbound_onion=*/false, /*network_key=*/0};
    CNode archive{/*id=*/197, /*sock=*/nullptr, CAddress{},
                  /*nKeyedNetGroupIn=*/1, /*nLocalHostNonceIn=*/0,
                  CAddress{}, /*addrNameIn=*/"frontier-archive",
                  ConnectionType::OUTBOUND_FULL_RELAY,
                  /*inbound_onion=*/false, /*network_key=*/0};
    connman.Handshake(miner, /*successfully_connected=*/true, miner_services,
                      miner_services, PROTOCOL_VERSION, /*relay_txs=*/true,
                      /*starting_height=*/tip->nHeight + kAhead);
    connman.Handshake(archive, /*successfully_connected=*/true,
                      archive_services, archive_services, PROTOCOL_VERSION,
                      /*relay_txs=*/true,
                      /*starting_height=*/tip->nHeight + kAhead);
    connman.FlushSendBuffer(miner);
    connman.FlushSendBuffer(archive);
    struct FinalizePeers {
        PeerManager& peerman;
        ConnmanTestMsg& connman;
        CNode& miner;
        CNode& archive;
        ~FinalizePeers()
        {
            peerman.FinalizeNode(miner);
            peerman.FinalizeNode(archive);
            connman.RemoveTestNode(miner);
            connman.RemoveTestNode(archive);
        }
    } finalize{peerman, connman, miner, archive};

    std::vector<CBlock> hdrs;
    hdrs.reserve(headers.size());
    {
        LOCK(::cs_main);
        for (CBlockIndex* idx : headers) {
            hdrs.emplace_back(idx->GetBlockHeader());
        }
    }
    BOOST_REQUIRE(connman.ReceiveMsgFrom(
        miner, NetMsg::Make(NetMsgType::HEADERS, TX_WITH_WITNESS(hdrs))));
    miner.fPauseSend = false;
    (void)connman.ProcessMessagesOnce(miner);
    BOOST_REQUIRE(connman.ReceiveMsgFrom(
        archive, NetMsg::Make(NetMsgType::HEADERS, TX_WITH_WITNESS(hdrs))));
    archive.fPauseSend = false;
    (void)connman.ProcessMessagesOnce(archive);

    BOOST_CHECK(peerman.SendMessages(&miner));
    CNodeStateStats miner_stats;
    BOOST_REQUIRE(peerman.GetNodeStateStats(miner.GetId(), miner_stats));
    BOOST_CHECK(miner_stats.vHeightInFlight.empty());
    BOOST_CHECK(!HasQueuedMessageType(miner, NetMsgType::GETDATA));

    BOOST_CHECK(peerman.SendMessages(&archive));
    CNodeStateStats archive_stats;
    BOOST_REQUIRE(peerman.GetNodeStateStats(archive.GetId(), archive_stats));
    BOOST_REQUIRE_EQUAL(archive_stats.vHeightInFlight.size(), 1U);
    BOOST_CHECK_EQUAL(archive_stats.vHeightInFlight.front(), tip->nHeight + 1);
    // HeadersDirectFetch may already have emitted GETDATA while processing
    // HEADERS; SendMessages then has nothing new to queue. In-flight is the
    // request.
    NeutralizeUnconnectedHeaders(chainman);
    peerman.ResetMatMulVerifyAdmissionForTest();
}

// PR 124 / MendeMatthias 2026-08-26: MaybeSeedGpuSignedFrontierBestKnown
// used to assign BestKnown = local signed-frontier seed even when the peer
// already advertised a higher chain. A competing *higher* BestKnown is not
// "usable for catch-up" (it does not extend the active tip), so the older
// best_known_usable guard does not fire — the raise check is what stops the
// pin.
BOOST_AUTO_TEST_CASE(signed_frontier_seed_does_not_lower_higher_best_known)
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
        std::move(config), /*trusted_mirror=*/true, /*serve=*/false,
        std::chrono::milliseconds{50}, error));
    BOOST_REQUIRE(node::matmul_trusted::IsTrustedMirror());
    struct MirrorReset {
        ~MirrorReset() { node::matmul_trusted::ResetForTest(); }
    } mirror_reset;

    ChainstateManager& chainman{*Assert(m_node.chainman)};
    PeerManager& peerman{*Assert(m_node.peerman)};
    ConnmanTestMsg& connman{static_cast<ConnmanTestMsg&>(*m_node.connman)};
    const CBlockIndex* starting_tip{
        WITH_LOCK(::cs_main, return chainman.ActiveChain().Tip())};
    BOOST_REQUIRE(starting_tip != nullptr);
    if (starting_tip->pprev == nullptr) {
        // Isolation: this suite's shared fixture is genesis. The competing
        // BestKnown must fork below the active tip, so mine one body first.
        mineBlock(m_node, std::chrono::seconds{starting_tip->GetBlockTime() + 1});
        starting_tip = WITH_LOCK(::cs_main, return chainman.ActiveChain().Tip());
        BOOST_REQUIRE(starting_tip != nullptr);
        peerman.SetBestBlock(starting_tip->nHeight,
                             std::chrono::seconds{starting_tip->GetBlockTime()});
    }
    BOOST_REQUIRE(starting_tip->pprev != nullptr);
    SetMockTime(std::chrono::seconds{starting_tip->GetBlockTime() + 3600});
    BOOST_REQUIRE(!chainman.IsInitialBlockDownload());
    peerman.SetBestBlock(starting_tip->nHeight,
                         std::chrono::seconds{starting_tip->GetBlockTime()});

    const uint256 tip_hash{starting_tip->GetBlockHash()};
    const int32_t tip_height{starting_tip->nHeight};
    BOOST_REQUIRE(node::matmul_trusted::SignAuthoritative(tip_hash, tip_height) ==
                  matmul::trusted::AddResult::Accepted);

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

    const CBlockIndex* walk{starting_tip};
    std::vector<CBlockIndex*> tip_suffix;
    for (int i = 0; i < 3; ++i) {
        CBlockIndex* nxt{make_header(*walk, 0xa10u + static_cast<unsigned int>(i))};
        tip_suffix.push_back(nxt);
        walk = nxt;
    }
    node::matmul_trusted::NoteAcceptedAttestationHeight(
        tip_suffix.back()->nHeight, tip_suffix.back()->GetBlockHash());

    const CBlockIndex* fork_parent{starting_tip->pprev};
    std::vector<CBlockIndex*> competing;
    const CBlockIndex* fork_walk{fork_parent};
    for (int i = 0; i < 8; ++i) {
        CBlockIndex* nxt{
            make_header(*fork_walk, 0xb20u + static_cast<unsigned int>(i))};
        competing.push_back(nxt);
        fork_walk = nxt;
    }
    BOOST_REQUIRE_GT(competing.back()->nHeight, tip_suffix.back()->nHeight);

    const ServiceFlags archive_services{ServiceFlags(
        NODE_NETWORK | NODE_WITNESS | NODE_MATMUL_ATTESTATION_ARCHIVE |
        NODE_MATMUL_TRUSTED_MIRROR)};
    CNode archive{/*id=*/198, /*sock=*/nullptr, CAddress{},
                  /*nKeyedNetGroupIn=*/1, /*nLocalHostNonceIn=*/0,
                  CAddress{}, /*addrNameIn=*/"seed-raise-archive",
                  ConnectionType::OUTBOUND_FULL_RELAY,
                  /*inbound_onion=*/false, /*network_key=*/0};
    connman.Handshake(archive, /*successfully_connected=*/true,
                      archive_services, archive_services, PROTOCOL_VERSION,
                      /*relay_txs=*/true,
                      /*starting_height=*/competing.back()->nHeight);
    connman.AddTestNode(archive);
    connman.FlushSendBuffer(archive);
    struct FinalizeArchive {
        PeerManager& peerman;
        ConnmanTestMsg& connman;
        CNode& archive;
        ~FinalizeArchive()
        {
            peerman.FinalizeNode(archive);
            connman.RemoveTestNode(archive);
        }
    } finalize{peerman, connman, archive};

    std::vector<CBlock> competing_hdrs;
    competing_hdrs.reserve(competing.size());
    {
        LOCK(::cs_main);
        for (CBlockIndex* idx : competing) {
            competing_hdrs.emplace_back(idx->GetBlockHeader());
        }
    }
    BOOST_REQUIRE(connman.ReceiveMsgFrom(
        archive, NetMsg::Make(NetMsgType::HEADERS, TX_WITH_WITNESS(competing_hdrs))));
    archive.fPauseSend = false;
    (void)connman.ProcessMessagesOnce(archive);
    CNodeStateStats before_seed;
    BOOST_REQUIRE(peerman.GetNodeStateStats(archive.GetId(), before_seed));
    BOOST_CHECK_EQUAL(before_seed.nSyncHeight, competing.back()->nHeight);

    BOOST_CHECK(peerman.SendMessages(&archive));
    CNodeStateStats after_seed;
    BOOST_REQUIRE(peerman.GetNodeStateStats(archive.GetId(), after_seed));
    BOOST_CHECK_EQUAL(after_seed.nSyncHeight, competing.back()->nHeight);
    BOOST_CHECK_NE(after_seed.nSyncHeight, tip_suffix.back()->nHeight);

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
               ConnectionType::MANUAL,
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
        if (persisted != nullptr &&
            !chainman.ActiveChain().Contains(persisted)) {
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

//! Documentation-range IPv4 so BanHammeringPeer actually Ban()s. 127/8 is
//! IsLocal and only disconnects (live signer isolation needs the 24h ban).
CService PeermanPublicService()
{
    return LookupNumeric("203.0.113.8", Params().GetDefaultPort());
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

//! Header+body whose parent is not the connected tip (sibling of the tip,
//! or a grandchild). CreateNewBlock always parents the active tip.
CBlock MineBlockOnParent(const node::NodeContext& node,
                         const uint256& prev_hash,
                         int32_t height,
                         uint32_t n_time,
                         int64_t median_time_past)
{
    CBlock block = node::BlockAssembler{
        node.chainman->ActiveChainstate(), nullptr, {}, node}
                       .CreateNewBlock()
                       ->block;
    block.hashPrevBlock = prev_hash;
    block.nTime = n_time;
    {
        CMutableTransaction coinbase{*block.vtx[0]};
        coinbase.vin[0].scriptSig = CScript() << height << OP_0;
        block.vtx[0] = MakeTransactionRef(coinbase);
    }
    block.hashMerkleRoot = BlockMerkleRoot(block);
    BOOST_REQUIRE(MineHeaderForConsensus(
        block, height, node.chainman->GetConsensus(), 5'000'000,
        median_time_past));
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

// Occupier header job is unfollowed before RCADMIT so it charges the
// 1/min peer window (progress-lane bypass does not fire). Honest body
// then misses at ConsumeMatMulRCPeerBudgetForHandoff and is retained.
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
    // Cap-one so the honest RCADMIT cannot enqueue a second header job
    // (that would make CanHandoffAuthenticatedTip false for the body).
    consensus.nMatMulRCMaxPendingVerifications = 1;

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

    auto pin_best = [&](const uint256& hash) {
        LOCK(::cs_main);
        CBlockIndex* idx{m_node.chainman->m_blockman.LookupBlockIndex(hash)};
        BOOST_REQUIRE(idx != nullptr);
        m_node.chainman->SetBestHeader(idx);
        return idx;
    };

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
    // The first-arriving tip-child becomes m_best_header, so its RCADMIT
    // would take the authenticated-progress lane (net_processing.cpp
    // ConsumeMatMulVerificationBudgetForPeer) and never charge the 1/min
    // peer window. Unfollow it before the ticket so the header job is a
    // real budget debit; the honest body can then miss at
    // ConsumeMatMulRCPeerBudgetForHandoff.
    pin_best(tip->GetBlockHash());
    {
        LOCK(::cs_main);
        const CBlockIndex* competing_idx{
            m_node.chainman->m_blockman.LookupBlockIndex(competing.GetHash())};
        BOOST_REQUIRE(competing_idx != nullptr);
        BOOST_REQUIRE(
            !m_node.chainman->IndexIsFollowedTipChild(tip, competing_idx));
    }
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
    // Equal-work tip-child twins tie-break on block hash (chain.cpp
    // PreferTrustAdjustedHeader). Pin the honest twin as followed so
    // MatMulMaySpendExactReplayGpu is deterministic across runs.
    {
        LOCK(::cs_main);
        CBlockIndex* honest_idx{
            m_node.chainman->m_blockman.LookupBlockIndex(honest_hash)};
        BOOST_REQUIRE(honest_idx != nullptr);
        m_node.chainman->SetBestHeader(honest_idx);
        BOOST_REQUIRE(m_node.chainman->IndexIsFollowedTipChild(tip, honest_idx));
    }
    BOOST_CHECK(!peer.fDisconnect);
    connman.FlushSendBuffer(peer);
    BOOST_REQUIRE(connman.ReceiveMsgFrom(
        peer, NetMsg::Make(NetMsgType::RCADMIT, honest_ticket)));
    peer.fPauseSend = false;
    (void)connman.ProcessMessagesOnce(peer);
    connman.FlushSendBuffer(peer);
    {
        ASSERT_DEBUG_LOG("RC handoff per-peer verification budget exhausted");
        BOOST_REQUIRE(connman.ReceiveMsgFrom(
            peer, NetMsg::Make(NetMsgType::BLOCK, TX_WITH_WITNESS(honest))));
        peer.fPauseSend = false;
        (void)connman.ProcessMessagesOnce(peer);
    }

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
    gate.Release();
    BOOST_REQUIRE(PeermanWaitFor([&] { return gate.running.load() == 0; }));
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

    // Late MMATTEST quorum authenticates the sibling. F3
    // AdvanceLastCommonPastActiveTip still drops same-height sibling holes
    // so they cannot occupy inflight (FindLowestMissingBody on a fork is
    // not a descendant of the connected tip). GETDATA for that body is a
    // grandchild/descendant path, not this sibling.
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

    {
        LOCK(::cs_main);
        CBlockIndex* competing_idx{
            m_node.chainman->m_blockman.LookupBlockIndex(competing_hash)};
        BOOST_REQUIRE(competing_idx != nullptr);
        m_node.chainman->SetBestHeader(competing_idx);
        BOOST_CHECK_EQUAL(competing_idx->nStatus & BLOCK_HAVE_DATA, 0);
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
                      services, PROTOCOL_VERSION, /*relay_txs=*/true,
                      /*starting_height=*/tip->nHeight + 2);
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
    connman.FlushSendBuffer(source);
    (void)peerman.SendMessages(&source);
    CNodeStateStats source_stats;
    BOOST_REQUIRE(peerman.GetNodeStateStats(source.GetId(), source_stats));
    BOOST_CHECK(!source.fDisconnect);
    BOOST_CHECK(source_stats.vHeightInFlight.empty());
    BOOST_CHECK(!HasQueuedMessageType(source, NetMsgType::GETDATA));

    {
        LOCK(::cs_main);
        m_node.chainman->SetBestHeader(
            const_cast<CBlockIndex*>(m_node.chainman->ActiveTip()));
        CBlockIndex* followed_idx{
            m_node.chainman->m_blockman.LookupBlockIndex(followed.GetHash())};
        // Do not strip HAVE_DATA from a block still on the active chain:
        // later DisconnectTip then fatal-errors "Failed to read block" and
        // poisons the shared peerman_tests fixture.
        if (followed_idx != nullptr &&
            !m_node.chainman->ActiveChain().Contains(followed_idx)) {
            followed_idx->nStatus &= ~BLOCK_HAVE_DATA;
            followed_idx->nTx = 0;
            followed_idx->m_chain_tx_count = 0;
            m_node.chainman->ActiveChainstate().setBlockIndexCandidates.erase(
                followed_idx);
        }
    }
    NeutralizeUnconnectedHeaders(*Assert(m_node.chainman));
    peerman.ResetMatMulVerifyAdmissionForTest();
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
    config.local_signer = signer;
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

    // Admission HEADER_ONLY-skips unattested catch-up suffixes. Attest first
    // so the grandchild persists without ExactReplay (GPU is the attestor).
    BOOST_REQUIRE(node::matmul_trusted::SignAuthoritative(
                      child.GetHash(), tip->nHeight + 1) ==
                  matmul::trusted::AddResult::Accepted);
    BOOST_REQUIRE(node::matmul_trusted::SignAuthoritative(
                      grandchild_hash, tip->nHeight + 2) ==
                  matmul::trusted::AddResult::Accepted);

    {
        DebugLogHelper no_header_only(
            "no GPU attestation; body not connected; GETMMATTEST then re-getdata",
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

BOOST_AUTO_TEST_CASE(catchup_grandchild_persists_without_gpu_on_signer)
{
    // Local signer / consensus miner: followed-suffix grandchildren must
    // persist HAVE_DATA so ConnectTip can ExactReplay in root-first order.
    // HEADER_ONLY-dropping them was the idle-GPU / frozen-tip stall.
    LOCK(NetEventsInterface::g_msgproc_mutex);

    node::matmul_trusted::ResetForTest();
    ResetSharedPeermanFixture(m_node);
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
        NODE_NETWORK | NODE_WITNESS | NODE_MATMUL_CONSENSUS)};
    CNode peer{/*id=*/223,
               /*sock=*/nullptr,
               CAddress{PeermanTestService(0x2300007f), NODE_NETWORK},
               /*nKeyedNetGroupIn=*/0x25,
               /*nLocalHostNonceIn=*/0,
               CAddress{},
               /*addrNameIn=*/"catchup-suffix-signer",
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
            "no GPU attestation; body not connected; GETMMATTEST then re-getdata",
            [](const std::string* line) {
                if (line != nullptr) {
                    throw std::runtime_error(
                        "followed-suffix grandchild must persist, not HEADER_ONLY");
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

// A followed tip-child cannot miss the global 1/min RC window: that
// window is bypassed when IsAuthenticatedChainProgressCandidate is true
// (ConsumeMatMulVerificationBudgetForPeer, authenticated_chain_progress &&
// rc_recompute). The second equal-height body is either followed (bypass)
// or not (ClaimConfigured refuses because the occupier already claimed →
// HEADER_ONLY). This case therefore cannot exhaust that window. It asserts
// the reachable property: an in-flight occupier does not disconnect the
// peer that delivers the second pinned tip-child body, which is retained.
BOOST_AUTO_TEST_CASE(second_tip_child_body_retained_while_occupier_holds_verify)
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
    {
        const auto ticket{GrindTicket(second.GetBlockHeader(), consensus.powLimit)};
        std::vector<CBlock> headers{CBlock{second.GetBlockHeader()}};
        BOOST_REQUIRE(connman.ReceiveMsgFrom(
            honest, NetMsg::Make(NetMsgType::HEADERS, TX_WITH_WITNESS(headers))));
        honest.fPauseSend = false;
        (void)connman.ProcessMessagesOnce(honest);
        {
            LOCK(::cs_main);
            CBlockIndex* second_idx{
                m_node.chainman->m_blockman.LookupBlockIndex(second.GetHash())};
            BOOST_REQUIRE(second_idx != nullptr);
            m_node.chainman->SetBestHeader(second_idx);
            BOOST_REQUIRE(
                m_node.chainman->IndexIsFollowedTipChild(tip, second_idx));
        }
        connman.FlushSendBuffer(honest);
        BOOST_REQUIRE(connman.ReceiveMsgFrom(
            honest, NetMsg::Make(NetMsgType::RCADMIT, ticket)));
        honest.fPauseSend = false;
        (void)connman.ProcessMessagesOnce(honest);
        connman.FlushSendBuffer(honest);
        BOOST_REQUIRE(connman.ReceiveMsgFrom(
            honest, NetMsg::Make(NetMsgType::BLOCK, TX_WITH_WITNESS(second))));
        honest.fPauseSend = false;
        (void)connman.ProcessMessagesOnce(honest);
    }

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
    gate.Release();
    BOOST_REQUIRE(PeermanWaitFor([&] { return gate.running.load() == 0; }));
    NeutralizeUnconnectedHeaders(*Assert(m_node.chainman));
    peerman.ResetMatMulVerifyAdmissionForTest();
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

    node::matmul_trusted::ResetForTest();
    ResetSharedPeermanFixture(m_node);
    ResetGlobalMatMulRCBudgetForTest();
    ConnmanTestMsg& connman = static_cast<ConnmanTestMsg&>(*m_node.connman);
    PeerManager& peerman = *m_node.peerman;
    struct Cleanup {
        node::NodeContext& node;
        PeerManager& peerman;
        ~Cleanup()
        {
            NeutralizeUnconnectedHeaders(*Assert(node.chainman));
            peerman.ResetMatMulVerifyAdmissionForTest();
        }
    } cleanup{m_node, peerman};

    Consensus::Params& consensus = const_cast<Consensus::Params&>(
        m_node.chainman->GetParams().GetConsensus());
    auto restore_heights{SaveMatMulHeights(consensus)};

    const CBlockIndex* tip{
        WITH_LOCK(::cs_main, return m_node.chainman->ActiveChain().Tip())};
    BOOST_REQUIRE(tip != nullptr);
    SetMockTime(std::chrono::seconds{tip->GetBlockTime() + 1});
    peerman.SetBestBlock(tip->nHeight, std::chrono::seconds{tip->GetBlockTime()});
    ActivateRcAtTip(consensus, *tip);
    consensus.nMatMulRCMaxPendingVerifications = 0;
    BOOST_REQUIRE(consensus.IsMatMulRCFamilyActive(tip->nHeight + 1));

    CBlock followed{MineTipChild(m_node, *tip, /*extra_time=*/0)};
    CBlock competing{MineTipChild(m_node, *tip, /*extra_time=*/1)};
    BOOST_REQUIRE(followed.GetHash() != competing.GetHash());

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

    std::vector<CBlock> followed_headers{CBlock{followed.GetBlockHeader()}};
    BOOST_REQUIRE(connman.ReceiveMsgFrom(
        peer, NetMsg::Make(NetMsgType::HEADERS, TX_WITH_WITNESS(followed_headers))));
    peer.fPauseSend = false;
    (void)connman.ProcessMessagesOnce(peer);
    BOOST_CHECK(peerman.SendMessages(&peer));
    connman.FlushSendBuffer(peer);
    peer.fPauseSend = false;

    std::vector<CBlock> competing_headers{CBlock{competing.GetBlockHeader()}};
    BOOST_REQUIRE(connman.ReceiveMsgFrom(
        peer, NetMsg::Make(NetMsgType::HEADERS, TX_WITH_WITNESS(competing_headers))));
    peer.fPauseSend = false;
    (void)connman.ProcessMessagesOnce(peer);
    connman.FlushSendBuffer(peer);
    peer.fPauseSend = false;

    const CBlock* sibling{&competing};
    {
        LOCK(::cs_main);
        const CBlockIndex* followed_idx{
            m_node.chainman->m_blockman.LookupBlockIndex(followed.GetHash())};
        const CBlockIndex* competing_idx{
            m_node.chainman->m_blockman.LookupBlockIndex(competing.GetHash())};
        BOOST_REQUIRE(followed_idx != nullptr);
        BOOST_REQUIRE(competing_idx != nullptr);
        const bool followed_is_unique{m_node.chainman->IndexIsFollowedTipChild(
            m_node.chainman->ActiveTip(), followed_idx)};
        const bool competing_is_unique{m_node.chainman->IndexIsFollowedTipChild(
            m_node.chainman->ActiveTip(), competing_idx)};
        BOOST_REQUIRE(followed_is_unique != competing_is_unique);
        sibling = followed_is_unique ? &competing : &followed;
    }

    {
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
            peer, NetMsg::Make(NetMsgType::BLOCK, TX_WITH_WITNESS(*sibling))));
        peer.fPauseSend = false;
        (void)connman.ProcessMessagesOnce(peer);
    }
    BOOST_CHECK(!peer.fDisconnect);
    BOOST_CHECK(peerman.HasMatMulRetainedBodyForTest(sibling->GetHash()));
    {
        LOCK(::cs_main);
        const CBlockIndex* indexed{
            m_node.chainman->m_blockman.LookupBlockIndex(sibling->GetHash())};
        BOOST_REQUIRE(indexed != nullptr);
        BOOST_CHECK_EQUAL(indexed->nStatus & BLOCK_HAVE_DATA, 0);
        BOOST_CHECK_EQUAL(indexed->nStatus & BLOCK_EXACT_REPLAY_VERIFIED, 0);
        BOOST_REQUIRE(!m_node.chainman->IndexIsFollowedTipChild(
            m_node.chainman->ActiveTip(), indexed));
    }

    connman.FlushSendBuffer(peer);
    for (int i = 0; i < 5; ++i) {
        BOOST_CHECK(peerman.SendMessages(&peer));
        BOOST_CHECK(!peer.fDisconnect);
        connman.FlushSendBuffer(peer);
        peer.fPauseSend = false;
    }
}

// v0.34.2 network-wide deadlock (jarekpiot, independently confirmed on
// macpro2; dixonping asked for this exact shape). One linear tip-child,
// no competing sibling at that height, active tip past the last attested
// block so nAuthenticatedChainWork < nChainWork. Tag v0.34.2 classified
// that child as competing, subtracted one work-unit from a one-job cap,
// and never ExactReplayed. The child must take the authenticated lane,
// occupy the reserved RC slot, ExactReplay, and connect.
BOOST_AUTO_TEST_CASE(linear_tip_child_replays_when_authenticated_work_lags)
{
    LOCK(NetEventsInterface::g_msgproc_mutex);

    node::matmul_trusted::ResetForTest();
    ResetSharedPeermanFixture(m_node);
    ResetGlobalMatMulRCBudgetForTest();
    ConnmanTestMsg& connman = static_cast<ConnmanTestMsg&>(*m_node.connman);
    PeerManager& peerman = *m_node.peerman;

    auto& mode = const_cast<kernel::MatMulValidationMode&>(
        m_node.chainman->m_options.matmul_validation_mode);
    const auto saved_mode{mode};
    struct RestoreMode {
        kernel::MatMulValidationMode& mode;
        kernel::MatMulValidationMode saved;
        ~RestoreMode() { mode = saved; }
    } restore_mode{mode, saved_mode};
    mode = kernel::MatMulValidationMode::CONSENSUS;

    Consensus::Params& consensus = const_cast<Consensus::Params&>(
        m_node.chainman->GetParams().GetConsensus());
    auto restore_heights{SaveMatMulHeights(consensus)};

    const CBlockIndex* tip{
        WITH_LOCK(::cs_main, return m_node.chainman->ActiveChain().Tip())};
    BOOST_REQUIRE(tip != nullptr);
    SetMockTime(std::chrono::seconds{tip->GetBlockTime() + 1});
    peerman.SetBestBlock(tip->nHeight, std::chrono::seconds{tip->GetBlockTime()});
    ActivateRcAtTip(consensus, *tip);
    // Production deadlock: one-job pending cap. Unthrottle the 1/min
    // rate windows so a budget miss cannot masquerade as the lane bug.
    consensus.nMatMulRCMaxPendingVerifications = 1;
    consensus.nMatMulRCPeerVerifyBudgetPerMin = 16;
    consensus.nMatMulRCGlobalVerifyBudgetPerMin = 16;
    BOOST_REQUIRE(consensus.IsMatMulRCFamilyActive(tip->nHeight + 1));
    BOOST_REQUIRE_EQUAL(MatMulRCWorkUnits(consensus, tip->nHeight + 1), 1U);

    {
        LOCK(::cs_main);
        CBlockIndex* tip_nc{
            const_cast<CBlockIndex*>(m_node.chainman->ActiveTip())};
        BOOST_REQUIRE(tip_nc != nullptr);
        BOOST_REQUIRE(tip_nc->nChainWork > 0);
        BOOST_REQUIRE(tip_nc->nAuthenticatedChainWork == tip_nc->nChainWork);
        tip_nc->nAuthenticatedChainWork -= 1;
        BOOST_REQUIRE(tip_nc->nAuthenticatedChainWork < tip_nc->nChainWork);
    }

    std::atomic<bool> replayed{false};
    CBlock child{MineTipChild(m_node, *tip, /*extra_time=*/0)};
    const uint256 child_hash{child.GetHash()};
    BOOST_REQUIRE(child.hashPrevBlock == tip->GetBlockHash());
    peerman.InstallMatMulVerifyOverrideForTest(
        [&](const CBlock& block, int32_t, std::optional<int64_t>) {
            if (block.GetHash() == child_hash) {
                replayed.store(true, std::memory_order_relaxed);
            }
            return true;
        });
    SetMatMulExactReplayUnderReleasedCsMainHookForTest([&]() -> std::optional<bool> {
        replayed.store(true, std::memory_order_relaxed);
        return true;
    });
    struct ClearOverride {
        PeerManager& peerman;
        ~ClearOverride()
        {
            peerman.InstallMatMulVerifyOverrideForTest({});
            SetMatMulExactReplayUnderReleasedCsMainHookForTest(nullptr);
        }
    } clear_override{peerman};

    const ServiceFlags services{ServiceFlags(
        NODE_NETWORK | NODE_WITNESS | NODE_MATMUL_CONSENSUS)};
    CNode peer{/*id=*/224,
               /*sock=*/nullptr,
               CAddress{PeermanTestService(0x1800007f), NODE_NETWORK},
               /*nKeyedNetGroupIn=*/0x18,
               /*nLocalHostNonceIn=*/0,
               CAddress{},
               /*addrNameIn=*/"linear-unattested-tip-child",
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

    const auto ticket{GrindTicket(child.GetBlockHeader(), consensus.powLimit)};
    std::vector<CBlock> headers{CBlock{child.GetBlockHeader()}};
    BOOST_REQUIRE(connman.ReceiveMsgFrom(
        peer, NetMsg::Make(NetMsgType::HEADERS, TX_WITH_WITNESS(headers))));
    peer.fPauseSend = false;
    (void)connman.ProcessMessagesOnce(peer);
    BOOST_CHECK(peerman.SendMessages(&peer));
    {
        LOCK(::cs_main);
        int at_height{0};
        for (const auto& [hash, index] : m_node.chainman->m_blockman.m_block_index) {
            (void)hash;
            if (index.nHeight == tip->nHeight + 1) ++at_height;
        }
        BOOST_REQUIRE_EQUAL(at_height, 1);
        const CBlockIndex* child_idx{
            m_node.chainman->m_blockman.LookupBlockIndex(child_hash)};
        BOOST_REQUIRE(child_idx != nullptr);
        BOOST_REQUIRE(child_idx->pprev == m_node.chainman->ActiveTip());
        BOOST_REQUIRE(m_node.chainman->ActiveTip()->nAuthenticatedChainWork <
                      m_node.chainman->ActiveTip()->nChainWork);
    }

    connman.FlushSendBuffer(peer);
    BOOST_REQUIRE(connman.ReceiveMsgFrom(
        peer, NetMsg::Make(NetMsgType::RCADMIT, ticket)));
    peer.fPauseSend = false;
    (void)connman.ProcessMessagesOnce(peer);
    connman.FlushSendBuffer(peer);

    {
        DebugLogHelper no_cap(
            "MatMul pending verification cap reached",
            [](const std::string* line) {
                if (line != nullptr) {
                    throw std::runtime_error(
                        "linear tip-child hit the competing pending cap "
                        "(v0.34.2 deadlock still present)");
                }
                return false;
            });
        BOOST_REQUIRE(connman.ReceiveMsgFrom(
            peer, NetMsg::Make(NetMsgType::BLOCK, TX_WITH_WITNESS(child))));
        peer.fPauseSend = false;
        (void)connman.ProcessMessagesOnce(peer);
    }
    BOOST_CHECK(!peer.fDisconnect);
    BOOST_CHECK(!peerman.HasMatMulRetainedBodyForTest(child_hash));

    BOOST_REQUIRE(PeermanWaitFor([&] {
        LOCK(::cs_main);
        const CBlockIndex* idx{
            m_node.chainman->m_blockman.LookupBlockIndex(child_hash)};
        return idx != nullptr &&
               (idx->nStatus & BLOCK_EXACT_REPLAY_VERIFIED) != 0 &&
               (idx->nStatus & BLOCK_HAVE_DATA) != 0 &&
               m_node.chainman->ActiveChain().Contains(idx) &&
               idx->IsValid(BLOCK_VALID_SCRIPTS);
    }));
    BOOST_CHECK(replayed.load(std::memory_order_relaxed));
    BOOST_CHECK_EQUAL(
        WITH_LOCK(::cs_main,
                  return m_node.chainman->ActiveChain().Tip()->GetBlockHash()),
        child_hash);

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
    NeutralizeUnconnectedHeaders(*Assert(m_node.chainman));
    peerman.ResetMatMulVerifyAdmissionForTest();
}

// Consensus archive catch-up (rtx6000 2026-08-29): unique followed
// tip-child, no rcadmit, many headers already on the followed chain.
// Ticketless persist must ExactReplay in AcceptBlock and ConnectTip must
// move. Competing siblings stay off the GPU (no 51% shortcut).
BOOST_AUTO_TEST_CASE(ticketless_followed_tip_child_converges_without_rcadmit)
{
    LOCK(NetEventsInterface::g_msgproc_mutex);

    node::matmul_trusted::ResetForTest();
    ResetSharedPeermanFixture(m_node);
    ResetGlobalMatMulRCBudgetForTest();
    ConnmanTestMsg& connman = static_cast<ConnmanTestMsg&>(*m_node.connman);
    PeerManager& peerman = *m_node.peerman;

    auto& mode = const_cast<kernel::MatMulValidationMode&>(
        m_node.chainman->m_options.matmul_validation_mode);
    const auto saved_mode{mode};
    struct RestoreMode {
        kernel::MatMulValidationMode& mode;
        kernel::MatMulValidationMode saved;
        ~RestoreMode() { mode = saved; }
    } restore_mode{mode, saved_mode};
    mode = kernel::MatMulValidationMode::CONSENSUS;

    Consensus::Params& consensus = const_cast<Consensus::Params&>(
        m_node.chainman->GetParams().GetConsensus());
    auto restore_heights{SaveMatMulHeights(consensus)};

    const CBlockIndex* tip{
        WITH_LOCK(::cs_main, return m_node.chainman->ActiveChain().Tip())};
    BOOST_REQUIRE(tip != nullptr);
    SetMockTime(std::chrono::seconds{tip->GetBlockTime() + 1});
    peerman.SetBestBlock(tip->nHeight, std::chrono::seconds{tip->GetBlockTime()});
    ActivateRcAtTip(consensus, *tip);
    consensus.nMatMulRCMaxPendingVerifications = 1;
    consensus.nMatMulRCPeerVerifyBudgetPerMin = 16;
    consensus.nMatMulRCGlobalVerifyBudgetPerMin = 16;
    BOOST_REQUIRE(consensus.IsMatMulRCFamilyActive(tip->nHeight + 1));

    std::atomic<bool> replayed{false};
    SetMatMulExactReplayUnderReleasedCsMainHookForTest([&]() -> std::optional<bool> {
        replayed.store(true, std::memory_order_relaxed);
        return true;
    });
    struct Cleanup {
        node::NodeContext& node;
        PeerManager& peerman;
        ~Cleanup()
        {
            SetMatMulExactReplayUnderReleasedCsMainHookForTest(nullptr);
            NeutralizeUnconnectedHeaders(*Assert(node.chainman));
            peerman.ResetMatMulVerifyAdmissionForTest();
        }
    } cleanup{m_node, peerman};

    CBlock followed{MineTipChild(m_node, *tip, /*extra_time=*/0)};
    const uint256 followed_hash{followed.GetHash()};

    const ServiceFlags services{ServiceFlags(
        NODE_NETWORK | NODE_WITNESS | NODE_MATMUL_CONSENSUS)};
    CNode peer{/*id=*/240,
               /*sock=*/nullptr,
               CAddress{PeermanTestService(0x2800007f), NODE_NETWORK},
               /*nKeyedNetGroupIn=*/0x28,
               /*nLocalHostNonceIn=*/0,
               CAddress{},
               /*addrNameIn=*/"consensus-archive-catch-up",
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

    std::vector<CBlock> headers{CBlock{followed.GetBlockHeader()}};
    peer.fPauseSend = false;
    connman.FlushSendBuffer(peer);
    BOOST_REQUIRE(connman.ReceiveMsgFrom(
        peer, NetMsg::Make(NetMsgType::HEADERS, TX_WITH_WITNESS(headers))));
    peer.fPauseSend = false;
    (void)connman.ProcessMessagesOnce(peer);
    BOOST_CHECK(peerman.SendMessages(&peer));
    connman.FlushSendBuffer(peer);
    peer.fPauseSend = false;

    {
        LOCK(::cs_main);
        const CBlockIndex* followed_idx{
            m_node.chainman->m_blockman.LookupBlockIndex(followed_hash)};
        BOOST_REQUIRE(followed_idx != nullptr);
        BOOST_REQUIRE(m_node.chainman->IndexIsFollowedTipChild(
            m_node.chainman->ActiveTip(), followed_idx));
    }

    BOOST_REQUIRE(connman.ReceiveMsgFrom(
        peer, NetMsg::Make(NetMsgType::BLOCK, TX_WITH_WITNESS(followed))));
    peer.fPauseSend = false;
    (void)connman.ProcessMessagesOnce(peer);
    BOOST_CHECK(!peer.fDisconnect);

    BOOST_REQUIRE(PeermanWaitFor([&] {
        LOCK(::cs_main);
        const CBlockIndex* idx{
            m_node.chainman->m_blockman.LookupBlockIndex(followed_hash)};
        return idx != nullptr &&
               (idx->nStatus & BLOCK_EXACT_REPLAY_VERIFIED) != 0 &&
               (idx->nStatus & BLOCK_HAVE_DATA) != 0 &&
               m_node.chainman->ActiveChain().Contains(idx) &&
               idx->IsValid(BLOCK_VALID_SCRIPTS);
    }));
    BOOST_CHECK(replayed.load(std::memory_order_relaxed));
    BOOST_CHECK_EQUAL(
        WITH_LOCK(::cs_main,
                  return m_node.chainman->ActiveChain().Tip()->GetBlockHash()),
        followed_hash);

    CBlockIndex* connected{WITH_LOCK(::cs_main, {
        CBlockIndex* idx{
            m_node.chainman->m_blockman.LookupBlockIndex(followed_hash)};
        return (idx != nullptr && m_node.chainman->ActiveChain().Contains(idx))
                   ? idx
                   : nullptr;
    })};
    if (connected != nullptr) {
        BlockValidationState invalidate_state;
        (void)m_node.chainman->ActiveChainstate().InvalidateBlock(
            invalidate_state, connected);
    }
}

// Live rtx6000 2026-08-29: IBD latched off, competing valid-PoW HEADERS
// at/above the connected tip (withdrawn 0.34.1 fork 33c834f8 shape),
// m_best_header leaves IndexIsFollowedTipChild(tip, tip+1) false, so
// IndependentConsensusMaySpendExactReplayGpu used to refuse every body
// above tip. Honest suffix bodies that extend the active tip must still
// ExactReplay and ConnectTip. Competing non-extending headers stay
// HEADER_ONLY (no bodies sent for them here).
BOOST_AUTO_TEST_CASE(consensus_behind_competing_twin_headers_still_converges)
{
    LOCK(NetEventsInterface::g_msgproc_mutex);

    node::matmul_trusted::ResetForTest();
    ResetSharedPeermanFixture(m_node);
    ResetGlobalMatMulRCBudgetForTest();
    ConnmanTestMsg& connman = static_cast<ConnmanTestMsg&>(*m_node.connman);
    PeerManager& peerman = *m_node.peerman;

    auto& mode = const_cast<kernel::MatMulValidationMode&>(
        m_node.chainman->m_options.matmul_validation_mode);
    const auto saved_mode{mode};
    struct RestoreMode {
        kernel::MatMulValidationMode& mode;
        kernel::MatMulValidationMode saved;
        ~RestoreMode() { mode = saved; }
    } restore_mode{mode, saved_mode};
    mode = kernel::MatMulValidationMode::CONSENSUS;

    Consensus::Params& consensus = const_cast<Consensus::Params&>(
        m_node.chainman->GetParams().GetConsensus());
    auto restore_heights{SaveMatMulHeights(consensus)};

    const CBlockIndex* tip{
        WITH_LOCK(::cs_main, return m_node.chainman->ActiveChain().Tip())};
    BOOST_REQUIRE(tip != nullptr);
    m_node.chainman->m_cached_finished_ibd.store(true, std::memory_order_relaxed);
    BOOST_REQUIRE(!m_node.chainman->IsInitialBlockDownload());
    SetMockTime(std::chrono::seconds{tip->GetBlockTime() + 1});
    peerman.SetBestBlock(tip->nHeight, std::chrono::seconds{tip->GetBlockTime()});
    ActivateRcAtTip(consensus, *tip);
    consensus.nMatMulRCMaxPendingVerifications = 8;
    consensus.nMatMulRCPeerVerifyBudgetPerMin = 16;
    consensus.nMatMulRCGlobalVerifyBudgetPerMin = 16;

    std::atomic<int> replayed{0};
    SetMatMulExactReplayUnderReleasedCsMainHookForTest([&]() -> std::optional<bool> {
        replayed.fetch_add(1, std::memory_order_relaxed);
        return true;
    });
    struct Cleanup {
        node::NodeContext& node;
        PeerManager& peerman;
        ~Cleanup()
        {
            SetMatMulExactReplayUnderReleasedCsMainHookForTest(nullptr);
            NeutralizeUnconnectedHeaders(*Assert(node.chainman));
            peerman.ResetMatMulVerifyAdmissionForTest();
        }
    } cleanup{m_node, peerman};

    // Competing twin at/above T needs a fork from below the connected tip
    // (GetAncestor(T) != T). Genesis has no parent, so connect one base block.
    if (tip->pprev == nullptr) {
        CBlock base{MineTipChild(m_node, *tip, /*extra_time=*/0)};
        BOOST_REQUIRE(m_node.chainman->ProcessNewBlock(
            std::make_shared<const CBlock>(base), /*force_processing=*/true,
            /*min_pow_checked=*/true, nullptr));
        tip = WITH_LOCK(::cs_main, return m_node.chainman->ActiveChain().Tip());
        BOOST_REQUIRE(tip != nullptr);
        BOOST_REQUIRE(tip->pprev != nullptr);
        ActivateRcAtTip(consensus, *tip);
        peerman.SetBestBlock(tip->nHeight, std::chrono::seconds{tip->GetBlockTime()});
        SetMockTime(std::chrono::seconds{tip->GetBlockTime() + 1});
    }
    BOOST_REQUIRE(consensus.IsMatMulRCFamilyActive(tip->nHeight + 1));
    BOOST_REQUIRE(consensus.IsMatMulRCFamilyActive(tip->nHeight + 2));

    const CBlockIndex& fork_parent{*tip->pprev};
    CBlock competing_twin{MineBlockOnParent(
        m_node, fork_parent.GetBlockHash(), tip->nHeight,
        static_cast<uint32_t>(fork_parent.GetBlockTime() + 2),
        fork_parent.GetMedianTimePast())};
    BOOST_REQUIRE(competing_twin.GetHash() != tip->GetBlockHash());
    CBlock competing_1{MineBlockOnParent(
        m_node, competing_twin.GetHash(), tip->nHeight + 1,
        competing_twin.nTime + 1, competing_twin.GetBlockTime())};
    CBlock competing_2{MineBlockOnParent(
        m_node, competing_1.GetHash(), tip->nHeight + 2,
        competing_1.nTime + 1, competing_1.GetBlockTime())};
    CBlock competing_3{MineBlockOnParent(
        m_node, competing_2.GetHash(), tip->nHeight + 3,
        competing_2.nTime + 1, competing_2.GetBlockTime())};

    CBlock honest_child{MineTipChild(m_node, *tip, /*extra_time=*/0)};
    BOOST_REQUIRE(honest_child.hashPrevBlock == tip->GetBlockHash());
    CBlock honest_grand{MineBlockOnParent(
        m_node, honest_child.GetHash(), tip->nHeight + 2,
        honest_child.nTime + 1, honest_child.GetBlockTime())};
    const uint256 child_hash{honest_child.GetHash()};
    const uint256 grand_hash{honest_grand.GetHash()};

    const ServiceFlags services{ServiceFlags(
        NODE_NETWORK | NODE_WITNESS | NODE_MATMUL_CONSENSUS)};
    CNode peer{/*id=*/241,
               /*sock=*/nullptr,
               CAddress{PeermanTestService(0x2900007f), NODE_NETWORK},
               /*nKeyedNetGroupIn=*/0x29,
               /*nLocalHostNonceIn=*/0,
               CAddress{},
               /*addrNameIn=*/"rtx6000-competing-twin-catch-up",
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

    auto send_headers = [&](std::vector<CBlock> headers) {
        peer.fPauseSend = false;
        connman.FlushSendBuffer(peer);
        BOOST_REQUIRE(connman.ReceiveMsgFrom(
            peer, NetMsg::Make(NetMsgType::HEADERS, TX_WITH_WITNESS(headers))));
        peer.fPauseSend = false;
        (void)connman.ProcessMessagesOnce(peer);
        BOOST_CHECK(peerman.SendMessages(&peer));
        connman.FlushSendBuffer(peer);
        peer.fPauseSend = false;
    };

    send_headers({CBlock{competing_twin.GetBlockHeader()},
                  CBlock{competing_1.GetBlockHeader()},
                  CBlock{competing_2.GetBlockHeader()},
                  CBlock{competing_3.GetBlockHeader()}});
    send_headers({CBlock{honest_child.GetBlockHeader()},
                  CBlock{honest_grand.GetBlockHeader()}});

    {
        LOCK(::cs_main);
        const CBlockIndex* const connected_tip{m_node.chainman->ActiveTip()};
        const CBlockIndex* const best{m_node.chainman->m_best_header};
        const CBlockIndex* const child_idx{
            m_node.chainman->m_blockman.LookupBlockIndex(child_hash)};
        const CBlockIndex* const grand_idx{
            m_node.chainman->m_blockman.LookupBlockIndex(grand_hash)};
        BOOST_REQUIRE(connected_tip != nullptr);
        BOOST_REQUIRE(best != nullptr);
        BOOST_REQUIRE(child_idx != nullptr);
        BOOST_REQUIRE(grand_idx != nullptr);
        BOOST_REQUIRE(best->GetAncestor(connected_tip->nHeight) != connected_tip);
        BOOST_REQUIRE(!m_node.chainman->IndexIsFollowedTipChild(
            connected_tip, child_idx));
        BOOST_REQUIRE(grand_idx->GetAncestor(connected_tip->nHeight) ==
                      connected_tip);
        BOOST_REQUIRE(node::matmul_trusted::IndependentConsensusMaySpendExactReplayGpu(
            grand_idx->pprev == connected_tip,
            grand_idx->GetAncestor(connected_tip->nHeight) == connected_tip,
            grand_idx->nHeight, connected_tip->nHeight, /*near_tip_depth=*/3,
            /*covered_by_attestation=*/false));
    }

    auto send_ticketed_body = [&](const CBlock& block) {
        const auto ticket{GrindTicket(block.GetBlockHeader(), consensus.powLimit)};
        peer.fPauseSend = false;
        connman.FlushSendBuffer(peer);
        BOOST_REQUIRE(connman.ReceiveMsgFrom(
            peer, NetMsg::Make(NetMsgType::RCADMIT, ticket)));
        peer.fPauseSend = false;
        (void)connman.ProcessMessagesOnce(peer);
        connman.FlushSendBuffer(peer);
        BOOST_REQUIRE(connman.ReceiveMsgFrom(
            peer, NetMsg::Make(NetMsgType::BLOCK, TX_WITH_WITNESS(block))));
        peer.fPauseSend = false;
        (void)connman.ProcessMessagesOnce(peer);
        connman.FlushSendBuffer(peer);
        peer.fPauseSend = false;
    };

    send_ticketed_body(honest_child);
    send_ticketed_body(honest_grand);
    BOOST_CHECK(!peer.fDisconnect);

    BOOST_REQUIRE(PeermanWaitFor([&] {
        LOCK(::cs_main);
        const CBlockIndex* idx{
            m_node.chainman->m_blockman.LookupBlockIndex(grand_hash)};
        return idx != nullptr &&
               (idx->nStatus & BLOCK_EXACT_REPLAY_VERIFIED) != 0 &&
               (idx->nStatus & BLOCK_HAVE_DATA) != 0 &&
               m_node.chainman->ActiveChain().Contains(idx) &&
               idx->IsValid(BLOCK_VALID_SCRIPTS);
    }));
    BOOST_CHECK_GE(replayed.load(std::memory_order_relaxed), 1);
    BOOST_CHECK_EQUAL(
        WITH_LOCK(::cs_main,
                  return m_node.chainman->ActiveChain().Tip()->GetBlockHash()),
        grand_hash);
    {
        LOCK(::cs_main);
        const CBlockIndex* competing_idx{
            m_node.chainman->m_blockman.LookupBlockIndex(
                competing_twin.GetHash())};
        BOOST_REQUIRE(competing_idx != nullptr);
        BOOST_CHECK_EQUAL(competing_idx->nStatus & BLOCK_HAVE_DATA, 0);
        BOOST_CHECK(!m_node.chainman->ActiveChain().Contains(competing_idx));
    }

    CBlockIndex* connected{WITH_LOCK(::cs_main, {
        CBlockIndex* idx{
            m_node.chainman->m_blockman.LookupBlockIndex(grand_hash)};
        return (idx != nullptr && m_node.chainman->ActiveChain().Contains(idx))
                   ? idx
                   : nullptr;
    })};
    if (connected != nullptr) {
        BlockValidationState invalidate_state;
        (void)m_node.chainman->ActiveChainstate().InvalidateBlock(
            invalidate_state, connected);
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

    const ServiceFlags services{ServiceFlags(
        NODE_NETWORK | NODE_WITNESS | NODE_MATMUL_CONSENSUS |
        NODE_MATMUL_ATTESTATION_ARCHIVE)};
    CNode peer{/*id=*/223,
               /*sock=*/nullptr,
               CAddress{PeermanTestService(0x1700007f), NODE_NETWORK},
               /*nKeyedNetGroupIn=*/0x17,
               /*nLocalHostNonceIn=*/0,
               CAddress{},
               /*addrNameIn=*/"encdr-competing-sibling",
               ConnectionType::OUTBOUND_FULL_RELAY,
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
        ASSERT_DEBUG_LOG("no GPU attestation; body not connected; GETMMATTEST then re-getdata");
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

// Live 2026-08-24: attested tip at H, unattested HEADER_ONLY twin at H,
// miners already extended the twin. Skip-set GETDATA + ExactReplay requiring
// pprev==tip left inflight=0. After the twin is skipped, a pulled-ahead
// grandchild header must unsuppress GETDATA and ExactReplay the twin body.
// A lone EncDr sibling with no descendant stays HEADER_ONLY (test above).
BOOST_AUTO_TEST_CASE(local_signer_fetches_header_only_lost_twin_after_headers_pull_ahead)
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

    const CBlockIndex* parent{
        WITH_LOCK(::cs_main, return m_node.chainman->ActiveChain().Tip())};
    BOOST_REQUIRE(parent != nullptr);
    SetMockTime(std::chrono::seconds{parent->GetBlockTime() + 1});
    ActivateRcAtTip(consensus, *parent);
    peerman.SetBestBlock(parent->nHeight,
                         std::chrono::seconds{parent->GetBlockTime()});

    CBlock adopted{MineTipChild(m_node, *parent, /*extra_time=*/0)};
    CBlock competing{MineTipChild(m_node, *parent, /*extra_time=*/1)};
    BOOST_REQUIRE(adopted.GetHash() != competing.GetHash());
    const uint256 competing_hash{competing.GetHash()};

    CBlock grandchild = node::BlockAssembler{
        m_node.chainman->ActiveChainstate(), nullptr, {}, m_node}
                            .CreateNewBlock()
                            ->block;
    grandchild.hashPrevBlock = competing.GetHash();
    grandchild.nTime = competing.nTime + 1;
    {
        CMutableTransaction coinbase{*grandchild.vtx[0]};
        coinbase.vin[0].scriptSig = CScript() << (parent->nHeight + 2) << OP_0;
        grandchild.vtx[0] = MakeTransactionRef(coinbase);
    }
    grandchild.hashMerkleRoot = BlockMerkleRoot(grandchild);
    BOOST_REQUIRE(MineHeaderForConsensus(
        grandchild, parent->nHeight + 2, m_node.chainman->GetConsensus(),
        5'000'000, competing.GetBlockTime()));

    BOOST_REQUIRE(m_node.chainman->ProcessNewBlock(
        std::make_shared<const CBlock>(adopted), /*force_processing=*/true,
        /*min_pow_checked=*/true, nullptr));
    BOOST_CHECK_EQUAL(
        WITH_LOCK(::cs_main,
                  return m_node.chainman->ActiveChain().Tip()->GetBlockHash()),
        adopted.GetHash());
    if (!node::matmul_trusted::HasQuorum(adopted.GetHash(),
                                         parent->nHeight + 1)) {
        BOOST_REQUIRE(node::matmul_trusted::SignAuthoritative(
                          adopted.GetHash(), parent->nHeight + 1) ==
                      matmul::trusted::AddResult::Accepted);
    }

    const ServiceFlags services{ServiceFlags(
        NODE_NETWORK | NODE_WITNESS | NODE_MATMUL_CONSENSUS |
        NODE_MATMUL_ATTESTATION_ARCHIVE)};
    CNode peer{/*id=*/224,
               /*sock=*/nullptr,
               CAddress{PeermanTestService(0x1800007f), NODE_NETWORK},
               /*nKeyedNetGroupIn=*/0x18,
               /*nLocalHostNonceIn=*/0,
               CAddress{},
               /*addrNameIn=*/"lost-twin-pulled-ahead",
               ConnectionType::OUTBOUND_FULL_RELAY,
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

    std::vector<CBlock> competing_headers{CBlock{competing.GetBlockHeader()}};
    peer.fPauseSend = false;
    connman.FlushSendBuffer(peer);
    BOOST_REQUIRE(connman.ReceiveMsgFrom(
        peer, NetMsg::Make(NetMsgType::HEADERS,
                           TX_WITH_WITNESS(competing_headers))));
    peer.fPauseSend = false;
    (void)connman.ProcessMessagesOnce(peer);
    connman.FlushSendBuffer(peer);

    {
        ASSERT_DEBUG_LOG("no GPU attestation; body not connected; GETMMATTEST then re-getdata");
        peer.fPauseSend = false;
        connman.FlushSendBuffer(peer);
        BOOST_REQUIRE(connman.ReceiveMsgFrom(
            peer, NetMsg::Make(NetMsgType::BLOCK, TX_WITH_WITNESS(competing))));
        peer.fPauseSend = false;
        (void)connman.ProcessMessagesOnce(peer);
    }
    {
        LOCK(::cs_main);
        const CBlockIndex* idx{
            m_node.chainman->m_blockman.LookupBlockIndex(competing_hash)};
        BOOST_REQUIRE(idx != nullptr);
        BOOST_CHECK_EQUAL(idx->nStatus & BLOCK_HAVE_DATA, 0);
    }

    for (int i = 0; i < 5; ++i) {
        connman.FlushSendBuffer(peer);
        BOOST_CHECK(peerman.SendMessages(&peer));
        BOOST_CHECK_EQUAL(CountQueuedGetDataForHash(peer, competing_hash), 0);
        BOOST_CHECK(!peer.fDisconnect);
    }

    std::vector<CBlock> fork_headers{CBlock{competing.GetBlockHeader()},
                                     CBlock{grandchild.GetBlockHeader()}};
    peer.fPauseSend = false;
    connman.FlushSendBuffer(peer);
    BOOST_REQUIRE(connman.ReceiveMsgFrom(
        peer, NetMsg::Make(NetMsgType::HEADERS, TX_WITH_WITNESS(fork_headers))));
    peer.fPauseSend = false;
    (void)connman.ProcessMessagesOnce(peer);

    bool fetched{false};
    for (int i = 0; i < 10; ++i) {
        (void)peerman.SendMessages(&peer);
        if (CountQueuedGetDataForHash(peer, competing_hash) > 0 ||
            HasQueuedMessageType(peer, NetMsgType::GETDATA)) {
            fetched = true;
            break;
        }
        CNodeStateStats stats;
        BOOST_REQUIRE(peerman.GetNodeStateStats(peer.GetId(), stats));
        if (std::find(stats.vHeightInFlight.begin(), stats.vHeightInFlight.end(),
                      parent->nHeight + 1) != stats.vHeightInFlight.end()) {
            fetched = true;
            break;
        }
        connman.FlushSendBuffer(peer);
    }
    BOOST_CHECK(fetched);
    BOOST_CHECK_EQUAL(
        WITH_LOCK(::cs_main,
                  return m_node.chainman->ActiveChain().Tip()->GetBlockHash()),
        adopted.GetHash());

    {
        LOCK(::cs_main);
        m_node.chainman->SetBestHeader(
            const_cast<CBlockIndex*>(m_node.chainman->ActiveTip()));
    }
}

// Live 2026-08-24: after the signer attested 199296–199297, the unsigned
// twin at 199295 had less work than the new tip. Skip-set re-filled on the
// next EncDr body and GETDATA stayed root_header_only_skip. Fetch the
// ancestor twin once competing headers are already ahead of the moved tip.
BOOST_AUTO_TEST_CASE(local_signer_fetches_ancestor_lost_twin_after_tip_moved)
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

    const CBlockIndex* parent{
        WITH_LOCK(::cs_main, return m_node.chainman->ActiveChain().Tip())};
    BOOST_REQUIRE(parent != nullptr);
    SetMockTime(std::chrono::seconds{parent->GetBlockTime() + 1});
    ActivateRcAtTip(consensus, *parent);
    peerman.SetBestBlock(parent->nHeight,
                         std::chrono::seconds{parent->GetBlockTime()});

    CBlock adopted{MineTipChild(m_node, *parent, /*extra_time=*/0)};
    CBlock competing{MineTipChild(m_node, *parent, /*extra_time=*/1)};
    const uint256 competing_hash{competing.GetHash()};
    BOOST_REQUIRE(m_node.chainman->ProcessNewBlock(
        std::make_shared<const CBlock>(adopted), /*force_processing=*/true,
        /*min_pow_checked=*/true, nullptr));
    if (!node::matmul_trusted::HasQuorum(adopted.GetHash(),
                                         parent->nHeight + 1)) {
        BOOST_REQUIRE(node::matmul_trusted::SignAuthoritative(
                          adopted.GetHash(), parent->nHeight + 1) ==
                      matmul::trusted::AddResult::Accepted);
    }
    const CBlockIndex* after_adopted{
        WITH_LOCK(::cs_main, return m_node.chainman->ActiveChain().Tip())};
    CBlock adopted2{MineTipChild(m_node, *after_adopted, /*extra_time=*/0)};
    BOOST_REQUIRE(m_node.chainman->ProcessNewBlock(
        std::make_shared<const CBlock>(adopted2), /*force_processing=*/true,
        /*min_pow_checked=*/true, nullptr));
    if (!node::matmul_trusted::HasQuorum(adopted2.GetHash(),
                                         parent->nHeight + 2)) {
        BOOST_REQUIRE(node::matmul_trusted::SignAuthoritative(
                          adopted2.GetHash(), parent->nHeight + 2) ==
                      matmul::trusted::AddResult::Accepted);
    }
    BOOST_CHECK_EQUAL(
        WITH_LOCK(::cs_main,
                  return m_node.chainman->ActiveChain().Tip()->nHeight),
        parent->nHeight + 2);

    CBlock grandchild = node::BlockAssembler{
        m_node.chainman->ActiveChainstate(), nullptr, {}, m_node}
                            .CreateNewBlock()
                            ->block;
    grandchild.hashPrevBlock = competing.GetHash();
    grandchild.nTime = competing.nTime + 1;
    {
        CMutableTransaction coinbase{*grandchild.vtx[0]};
        coinbase.vin[0].scriptSig = CScript() << (parent->nHeight + 2) << OP_0;
        grandchild.vtx[0] = MakeTransactionRef(coinbase);
    }
    grandchild.hashMerkleRoot = BlockMerkleRoot(grandchild);
    BOOST_REQUIRE(MineHeaderForConsensus(
        grandchild, parent->nHeight + 2, m_node.chainman->GetConsensus(),
        5'000'000, competing.GetBlockTime()));

    CBlock great = node::BlockAssembler{
        m_node.chainman->ActiveChainstate(), nullptr, {}, m_node}
                       .CreateNewBlock()
                       ->block;
    great.hashPrevBlock = grandchild.GetHash();
    great.nTime = grandchild.nTime + 1;
    {
        CMutableTransaction coinbase{*great.vtx[0]};
        coinbase.vin[0].scriptSig = CScript() << (parent->nHeight + 3) << OP_0;
        great.vtx[0] = MakeTransactionRef(coinbase);
    }
    great.hashMerkleRoot = BlockMerkleRoot(great);
    BOOST_REQUIRE(MineHeaderForConsensus(
        great, parent->nHeight + 3, m_node.chainman->GetConsensus(),
        5'000'000, grandchild.GetBlockTime()));

    const ServiceFlags services{ServiceFlags(
        NODE_NETWORK | NODE_WITNESS | NODE_MATMUL_CONSENSUS |
        NODE_MATMUL_ATTESTATION_ARCHIVE)};
    CNode peer{/*id=*/225,
               /*sock=*/nullptr,
               CAddress{PeermanTestService(0x1900007f), NODE_NETWORK},
               /*nKeyedNetGroupIn=*/0x19,
               /*nLocalHostNonceIn=*/0,
               CAddress{},
               /*addrNameIn=*/"ancestor-lost-twin",
               ConnectionType::OUTBOUND_FULL_RELAY,
               /*inbound_onion=*/false,
               /*network_key=*/0};
    connman.Handshake(peer, /*successfully_connected=*/true, services, services,
                      PROTOCOL_VERSION, /*relay_txs=*/true,
                      /*starting_height=*/parent->nHeight + 10);
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

    std::vector<CBlock> fork_headers{CBlock{competing.GetBlockHeader()},
                                     CBlock{grandchild.GetBlockHeader()},
                                     CBlock{great.GetBlockHeader()}};
    BOOST_REQUIRE(connman.ReceiveMsgFrom(
        peer, NetMsg::Make(NetMsgType::HEADERS, TX_WITH_WITNESS(fork_headers))));
    peer.fPauseSend = false;
    (void)connman.ProcessMessagesOnce(peer);

    {
        LOCK(::cs_main);
        BOOST_REQUIRE_MESSAGE(
            m_node.chainman->m_blockman.LookupBlockIndex(competing_hash) != nullptr,
            "competing header not in index");
        BOOST_REQUIRE_MESSAGE(
            m_node.chainman->m_blockman.LookupBlockIndex(great.GetHash()) != nullptr,
            "great header not in index");
        const auto* tip{m_node.chainman->ActiveChain().Tip()};
        const auto* claimed{m_node.chainman->m_best_claimed_header};
        BOOST_REQUIRE(tip != nullptr);
        BOOST_REQUIRE_MESSAGE(
            claimed != nullptr && claimed->nHeight > tip->nHeight,
            strprintf("claimed height %d tip %d",
                      claimed ? claimed->nHeight : -1, tip->nHeight));
    }

    bool fetched{false};
    {
        CNodeStateStats stats;
        BOOST_REQUIRE(peerman.GetNodeStateStats(peer.GetId(), stats));
        if (CountQueuedGetDataForHash(peer, competing_hash) > 0 ||
            HasQueuedMessageType(peer, NetMsgType::GETDATA) ||
            std::find(stats.vHeightInFlight.begin(), stats.vHeightInFlight.end(),
                      parent->nHeight + 1) != stats.vHeightInFlight.end()) {
            fetched = true;
        }
    }
    for (int i = 0; i < 10 && !fetched; ++i) {
        (void)peerman.SendMessages(&peer);
        if (CountQueuedGetDataForHash(peer, competing_hash) > 0 ||
            HasQueuedMessageType(peer, NetMsgType::GETDATA)) {
            fetched = true;
            break;
        }
        CNodeStateStats stats;
        BOOST_REQUIRE(peerman.GetNodeStateStats(peer.GetId(), stats));
        if (std::find(stats.vHeightInFlight.begin(), stats.vHeightInFlight.end(),
                      parent->nHeight + 1) != stats.vHeightInFlight.end()) {
            fetched = true;
            break;
        }
        connman.FlushSendBuffer(peer);
    }
    BOOST_CHECK(fetched);
}

// PR 117 review: tip H, equal-work cousin at H, LCA H-2. After the unsigned
// fork-child at H-1 has HAVE_DATA, GETDATA must fetch the cousin. The
// same-parent arm does not match (cousin's parent is the fork-child).
BOOST_AUTO_TEST_CASE(local_signer_fetches_depth2_lost_twin_cousin)
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

    const CBlockIndex* parent{
        WITH_LOCK(::cs_main, return m_node.chainman->ActiveChain().Tip())};
    BOOST_REQUIRE(parent != nullptr);
    SetMockTime(std::chrono::seconds{parent->GetBlockTime() + 1});
    ActivateRcAtTip(consensus, *parent);
    peerman.SetBestBlock(parent->nHeight,
                         std::chrono::seconds{parent->GetBlockTime()});

    CBlock adopted{MineTipChild(m_node, *parent, /*extra_time=*/0)};
    CBlock competing{MineTipChild(m_node, *parent, /*extra_time=*/1)};
    BOOST_REQUIRE(m_node.chainman->ProcessNewBlock(
        std::make_shared<const CBlock>(adopted), /*force_processing=*/true,
        /*min_pow_checked=*/true, nullptr));
    if (!node::matmul_trusted::HasQuorum(adopted.GetHash(),
                                         parent->nHeight + 1)) {
        BOOST_REQUIRE(node::matmul_trusted::SignAuthoritative(
                          adopted.GetHash(), parent->nHeight + 1) ==
                      matmul::trusted::AddResult::Accepted);
    }
    const CBlockIndex* after_adopted{
        WITH_LOCK(::cs_main, return m_node.chainman->ActiveChain().Tip())};
    CBlock adopted2{MineTipChild(m_node, *after_adopted, /*extra_time=*/0)};
    BOOST_REQUIRE(m_node.chainman->ProcessNewBlock(
        std::make_shared<const CBlock>(adopted2), /*force_processing=*/true,
        /*min_pow_checked=*/true, nullptr));
    if (!node::matmul_trusted::HasQuorum(adopted2.GetHash(),
                                         parent->nHeight + 2)) {
        BOOST_REQUIRE(node::matmul_trusted::SignAuthoritative(
                          adopted2.GetHash(), parent->nHeight + 2) ==
                      matmul::trusted::AddResult::Accepted);
    }
    BOOST_REQUIRE(m_node.chainman->ProcessNewBlock(
        std::make_shared<const CBlock>(competing), /*force_processing=*/true,
        /*min_pow_checked=*/true, nullptr));
    BOOST_REQUIRE(PeermanWaitFor([&] {
        LOCK(::cs_main);
        const CBlockIndex* idx{m_node.chainman->m_blockman.LookupBlockIndex(
            competing.GetHash())};
        return idx != nullptr && (idx->nStatus & BLOCK_HAVE_DATA) != 0;
    }));
    BOOST_CHECK_EQUAL(
        WITH_LOCK(::cs_main,
                  return m_node.chainman->ActiveChain().Tip()->GetBlockHash()),
        adopted2.GetHash());

    CBlock cousin = node::BlockAssembler{
        m_node.chainman->ActiveChainstate(), nullptr, {}, m_node}
                        .CreateNewBlock()
                        ->block;
    cousin.hashPrevBlock = competing.GetHash();
    cousin.nTime = competing.nTime + 1;
    {
        CMutableTransaction coinbase{*cousin.vtx[0]};
        coinbase.vin[0].scriptSig = CScript() << (parent->nHeight + 2) << OP_0;
        cousin.vtx[0] = MakeTransactionRef(coinbase);
    }
    cousin.hashMerkleRoot = BlockMerkleRoot(cousin);
    BOOST_REQUIRE(MineHeaderForConsensus(
        cousin, parent->nHeight + 2, m_node.chainman->GetConsensus(),
        5'000'000, competing.GetBlockTime()));
    const uint256 cousin_hash{cousin.GetHash()};

    CBlock great = node::BlockAssembler{
        m_node.chainman->ActiveChainstate(), nullptr, {}, m_node}
                       .CreateNewBlock()
                       ->block;
    great.hashPrevBlock = cousin.GetHash();
    great.nTime = cousin.nTime + 1;
    {
        CMutableTransaction coinbase{*great.vtx[0]};
        coinbase.vin[0].scriptSig = CScript() << (parent->nHeight + 3) << OP_0;
        great.vtx[0] = MakeTransactionRef(coinbase);
    }
    great.hashMerkleRoot = BlockMerkleRoot(great);
    BOOST_REQUIRE(MineHeaderForConsensus(
        great, parent->nHeight + 3, m_node.chainman->GetConsensus(),
        5'000'000, cousin.GetBlockTime()));

    const ServiceFlags services{ServiceFlags(
        NODE_NETWORK | NODE_WITNESS | NODE_MATMUL_CONSENSUS |
        NODE_MATMUL_ATTESTATION_ARCHIVE)};
    CNode peer{/*id=*/226,
               /*sock=*/nullptr,
               CAddress{PeermanTestService(0x1a00007f), NODE_NETWORK},
               /*nKeyedNetGroupIn=*/0x1a,
               /*nLocalHostNonceIn=*/0,
               CAddress{},
               /*addrNameIn=*/"depth2-lost-twin-cousin",
               ConnectionType::OUTBOUND_FULL_RELAY,
               /*inbound_onion=*/false,
               /*network_key=*/0};
    connman.Handshake(peer, /*successfully_connected=*/true, services, services,
                      PROTOCOL_VERSION, /*relay_txs=*/true,
                      /*starting_height=*/parent->nHeight + 10);
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

    std::vector<CBlock> fork_headers{CBlock{competing.GetBlockHeader()},
                                     CBlock{cousin.GetBlockHeader()},
                                     CBlock{great.GetBlockHeader()}};
    BOOST_REQUIRE(connman.ReceiveMsgFrom(
        peer, NetMsg::Make(NetMsgType::HEADERS, TX_WITH_WITNESS(fork_headers))));
    peer.fPauseSend = false;
    (void)connman.ProcessMessagesOnce(peer);

    bool fetched{false};
    for (int i = 0; i < 10 && !fetched; ++i) {
        (void)peerman.SendMessages(&peer);
        if (CountQueuedGetDataForHash(peer, cousin_hash) > 0 ||
            HasQueuedMessageType(peer, NetMsgType::GETDATA)) {
            fetched = true;
            break;
        }
        CNodeStateStats stats;
        BOOST_REQUIRE(peerman.GetNodeStateStats(peer.GetId(), stats));
        if (std::find(stats.vHeightInFlight.begin(), stats.vHeightInFlight.end(),
                      parent->nHeight + 2) != stats.vHeightInFlight.end()) {
            fetched = true;
            break;
        }
        connman.FlushSendBuffer(peer);
    }
    BOOST_CHECK(fetched);
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
        NODE_NETWORK | NODE_WITNESS | NODE_MATMUL_CONSENSUS |
        NODE_MATMUL_ATTESTATION_ARCHIVE)};
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

BOOST_AUTO_TEST_CASE(archive_block_serve_helpers_and_gates_unchanged)
{
    using node::matmul_trusted::MsghandPreferArchiveLiveGetData;
    using node::matmul_trusted::MsghandSkipArchiveBlockGetData;
    using node::matmul_trusted::MsghandPeerIsArchiveServeTarget;
    using node::matmul_trusted::SignedFrontierPeerHadCatchUpBodiesAtConnect;
    using node::matmul_trusted::TrustedMirrorGpuHandshakeTimeout;

    BOOST_CHECK(MsghandPeerIsArchiveServeTarget(true, true));
    BOOST_CHECK(!MsghandPeerIsArchiveServeTarget(true, false));
    BOOST_CHECK(MsghandPreferArchiveLiveGetData(true, true));
    BOOST_CHECK(!MsghandPreferArchiveLiveGetData(true, false));
    BOOST_CHECK(!MsghandSkipArchiveBlockGetData(
        /*local_signer=*/true, /*worker=*/false, /*archive=*/true));
    BOOST_CHECK(MsghandSkipArchiveBlockGetData(true, true, true));
    BOOST_CHECK(!MsghandSkipArchiveBlockGetData(true, true, /*archive=*/false));
    BOOST_CHECK(!MsghandSkipArchiveBlockGetData(
        /*local_signer=*/false, true, true));

    // (c) behind-sibling starting_height gate: VERSION height must exceed tip.
    BOOST_CHECK(!SignedFrontierPeerHadCatchUpBodiesAtConnect(
        /*starting_height=*/190767, /*tip_height=*/190816));
    BOOST_CHECK(SignedFrontierPeerHadCatchUpBodiesAtConnect(190858, 190781));
    BOOST_CHECK(!SignedFrontierPeerHadCatchUpBodiesAtConnect(190781, 190781));

    // (d) handshake-dead timeouts: 15s never-received, 180s incomplete-with-recv.
    BOOST_CHECK_EQUAL(
        TrustedMirrorGpuHandshakeTimeout(std::chrono::seconds{60}, true,
                                         /*handshake_incomplete=*/true,
                                         /*never_received=*/true)
            .count(),
        15);
    BOOST_CHECK_EQUAL(
        TrustedMirrorGpuHandshakeTimeout(std::chrono::seconds{60}, true,
                                         /*handshake_incomplete=*/true,
                                         /*never_received=*/false)
            .count(),
        180);
}

BOOST_AUTO_TEST_CASE(archive_getdata_worker_serves_block_without_double_send)
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
        std::move(config), /*trusted_mirror=*/false, /*serve=*/false,
        std::chrono::milliseconds{50}, error));
    BOOST_REQUIRE(node::matmul_trusted::HasLocalSigner());
    struct SignerReset {
        ~SignerReset() { node::matmul_trusted::ResetForTest(); }
    } signer_reset;

    ChainstateManager& chainman{*Assert(m_node.chainman)};
    PeerManager& peerman{*Assert(m_node.peerman)};
    ConnmanTestMsg& connman{static_cast<ConnmanTestMsg&>(*m_node.connman)};
    const CBlockIndex* tip{
        WITH_LOCK(::cs_main, return chainman.ActiveChain().Tip())};
    BOOST_REQUIRE(tip != nullptr);
    BOOST_REQUIRE(tip->nStatus & BLOCK_HAVE_DATA);
    const uint256 tip_hash{tip->GetBlockHash()};

    const ServiceFlags miner_services{ServiceFlags(
        NODE_NETWORK | NODE_WITNESS | NODE_MATMUL_CONSENSUS)};
    const ServiceFlags archive_services{ServiceFlags(
        NODE_NETWORK | NODE_WITNESS | NODE_MATMUL_ATTESTATION_ARCHIVE |
        NODE_MATMUL_TRUSTED_MIRROR)};
    CNode miner{/*id=*/501, /*sock=*/nullptr, CAddress{},
                /*nKeyedNetGroupIn=*/0, /*nLocalHostNonceIn=*/0,
                CAddress{}, /*addrNameIn=*/"archive-serve-miner",
                ConnectionType::INBOUND,
                /*inbound_onion=*/false, /*network_key=*/0};
    CNode archive{/*id=*/502, /*sock=*/nullptr, CAddress{},
                  /*nKeyedNetGroupIn=*/1, /*nLocalHostNonceIn=*/0,
                  CAddress{}, /*addrNameIn=*/"archive-serve-archive",
                  ConnectionType::INBOUND,
                  /*inbound_onion=*/false, /*network_key=*/0};
    connman.Handshake(miner, /*successfully_connected=*/true, miner_services,
                      miner_services, PROTOCOL_VERSION, /*relay_txs=*/true);
    connman.Handshake(archive, /*successfully_connected=*/true,
                      archive_services, archive_services, PROTOCOL_VERSION,
                      /*relay_txs=*/true);
    connman.AddTestNode(miner);
    connman.AddTestNode(archive);
    connman.FlushSendBuffer(miner);
    connman.FlushSendBuffer(archive);
    struct FinalizePeers {
        PeerManager& peerman;
        ConnmanTestMsg& connman;
        CNode& miner;
        CNode& archive;
        ~FinalizePeers()
        {
            peerman.FinalizeNode(miner);
            peerman.FinalizeNode(archive);
            connman.RemoveTestNode(miner);
            connman.RemoveTestNode(archive);
            connman.SetArchiveBlockServeRunningForTest(false);
        }
    } finalize{peerman, connman, miner, archive};

    std::vector<CInv> inv{{MSG_BLOCK | MSG_WITNESS_FLAG, tip_hash}};

    // Fallback: worker not running, msghand still serves archive GETDATA.
    BOOST_REQUIRE(connman.ReceiveMsgFrom(
        archive, NetMsg::Make(NetMsgType::GETDATA, inv)));
    archive.fPauseSend = false;
    (void)connman.ProcessMessagesOnce(archive);
    BOOST_CHECK_EQUAL(CountQueuedMessageType(archive, NetMsgType::BLOCK), 1U);
    connman.FlushSendBuffer(archive);

    // Worker running: msghand leaves archive BLOCK queued; miner still 1-wide.
    connman.SetArchiveBlockServeRunningForTest(true);
    BOOST_REQUIRE(connman.ReceiveMsgFrom(
        archive, NetMsg::Make(NetMsgType::GETDATA, inv)));
    archive.fPauseSend = false;
    (void)connman.ProcessMessagesOnce(archive);
    BOOST_CHECK_EQUAL(CountQueuedMessageType(archive, NetMsgType::BLOCK), 0U);

    BOOST_REQUIRE(connman.ReceiveMsgFrom(
        miner, NetMsg::Make(NetMsgType::GETDATA, inv)));
    miner.fPauseSend = false;
    (void)connman.ProcessMessagesOnce(miner);
    BOOST_CHECK_EQUAL(CountQueuedMessageType(miner, NetMsgType::BLOCK), 1U);

    std::atomic<bool> interrupt{false};
    BOOST_CHECK(!peerman.ServeArchiveBlockGetData(interrupt));
    BOOST_CHECK_EQUAL(CountQueuedMessageType(archive, NetMsgType::BLOCK), 1U);
    BOOST_CHECK_EQUAL(CountQueuedMessageType(miner, NetMsgType::BLOCK), 1U);

    // Dual path must not double-send.
    (void)connman.ProcessMessagesOnce(archive);
    BOOST_CHECK(!peerman.ServeArchiveBlockGetData(interrupt));
    BOOST_CHECK_EQUAL(CountQueuedMessageType(archive, NetMsgType::BLOCK), 1U);
    BOOST_CHECK_EQUAL(CountQueuedMessageType(miner, NetMsgType::BLOCK), 1U);
}

// Live signer isolation: -matmulattestationserve=0 still SignAuthoritative
// and pushes MMATTEST to connected peers after ExactReplay, but inbound
// GETMMATTEST must not fan into cs_main (not_serving before the lock).
BOOST_AUTO_TEST_CASE(signer_serve_zero_pushes_new_attestations_refuses_getmmattest)
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
        std::move(config), /*trusted_mirror=*/false, /*serve=*/false,
        std::chrono::milliseconds{50}, error));
    BOOST_REQUIRE(node::matmul_trusted::HasLocalSigner());
    BOOST_REQUIRE(!node::matmul_trusted::ServesAttestations());
    BOOST_REQUIRE(!node::matmul_trusted::IsTrustedMirror());
    struct SignerReset {
        ~SignerReset() { node::matmul_trusted::ResetForTest(); }
    } signer_reset;

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

    CBlock child{MineTipChild(m_node, *parent, /*extra_time=*/0)};
    const uint256 child_hash{child.GetHash()};

    const ServiceFlags services{ServiceFlags(
        NODE_NETWORK | NODE_WITNESS | NODE_MATMUL_CONSENSUS)};
    CNode peer{/*id=*/403,
               /*sock=*/nullptr,
               CAddress{PeermanTestService(0x0f00007f), NODE_NETWORK},
               /*nKeyedNetGroupIn=*/0x0f,
               /*nLocalHostNonceIn=*/0,
               CAddress{},
               /*addrNameIn=*/"serve-zero-observer",
               ConnectionType::OUTBOUND_FULL_RELAY,
               /*inbound_onion=*/false,
               /*network_key=*/0};
    connman.Handshake(peer, /*successfully_connected=*/true, services, services,
                      PROTOCOL_VERSION, /*relay_txs=*/true);
    connman.AddTestNode(peer);
    connman.FlushSendBuffer(peer);
    m_node.validation_signals->RegisterValidationInterface(&peerman);
    struct UnregisterPeerman {
        ValidationSignals& signals;
        CValidationInterface* iface;
        ~UnregisterPeerman() { signals.UnregisterValidationInterface(iface); }
    } unregister{*m_node.validation_signals, &peerman};
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
    BOOST_CHECK(!peer.fDisconnect);

    BOOST_REQUIRE(PeermanWaitFor([&] {
        LOCK(::cs_main);
        const CBlockIndex* idx{
            m_node.chainman->m_blockman.LookupBlockIndex(child_hash)};
        return idx != nullptr &&
               (idx->nStatus & BLOCK_EXACT_REPLAY_VERIFIED) != 0 &&
               (idx->nStatus & BLOCK_HAVE_DATA) != 0 &&
               m_node.chainman->ActiveChain().Contains(idx) &&
               idx->IsValid(BLOCK_VALID_SCRIPTS);
    }));
    m_node.validation_signals->SyncWithValidationInterfaceQueue();
    BOOST_REQUIRE(PeermanWaitFor(
        [&] { return HasQueuedMessageType(peer, NetMsgType::MMATTEST); }));
    BOOST_CHECK(node::matmul_trusted::HasQuorum(child_hash, parent->nHeight + 1));
    connman.FlushSendBuffer(peer);

    peer.fPauseSend = false;
    BOOST_REQUIRE(connman.ReceiveMsgFrom(
        peer, NetMsg::Make(NetMsgType::GETMMATTEST, child_hash)));
    peer.fPauseSend = false;
    (void)connman.ProcessMessagesOnce(peer);
    BOOST_CHECK(!HasQueuedMessageType(peer, NetMsgType::MMATTEST));
    BOOST_CHECK(!peer.fDisconnect);
    BOOST_CHECK(!node::matmul_trusted::ServesAttestations());

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

// Issue 116: PersistMatMulExactReplayVerdict used to SignAuthoritative and
// return without MMATTEST, so a GETMMATTEST-triggered / header-first ExactReplay
// was stored and never announced. ProcessNewBlock here is AcceptBlock Persist
// without ProcessBlockSync. ProcessNewBlockFinished must still gossip (the
// generate/submitblock miss). The persist helper remains the header-first /
// historical reverify path.
BOOST_AUTO_TEST_CASE(exact_replay_persist_path_pushes_mmattest)
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
        std::move(config), /*trusted_mirror=*/false, /*serve=*/false,
        std::chrono::milliseconds{50}, error));
    BOOST_REQUIRE(node::matmul_trusted::HasLocalSigner());
    BOOST_REQUIRE(!node::matmul_trusted::ServesAttestations());
    struct SignerReset {
        ~SignerReset() { node::matmul_trusted::ResetForTest(); }
    } signer_reset;

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

    CBlock child{MineTipChild(m_node, *parent, /*extra_time=*/0)};
    const uint256 child_hash{child.GetHash()};

    const ServiceFlags services{ServiceFlags(
        NODE_NETWORK | NODE_WITNESS | NODE_MATMUL_CONSENSUS)};
    CNode peer{/*id=*/404,
               /*sock=*/nullptr,
               CAddress{PeermanTestService(0x1000007f), NODE_NETWORK},
               /*nKeyedNetGroupIn=*/0x10,
               /*nLocalHostNonceIn=*/0,
               CAddress{},
               /*addrNameIn=*/"persist-path-observer",
               ConnectionType::OUTBOUND_FULL_RELAY,
               /*inbound_onion=*/false,
               /*network_key=*/0};
    connman.Handshake(peer, /*successfully_connected=*/true, services, services,
                      PROTOCOL_VERSION, /*relay_txs=*/true);
    connman.AddTestNode(peer);
    connman.FlushSendBuffer(peer);
    m_node.validation_signals->RegisterValidationInterface(&peerman);
    struct UnregisterPeerman {
        ValidationSignals& signals;
        CValidationInterface* iface;
        ~UnregisterPeerman() { signals.UnregisterValidationInterface(iface); }
    } unregister{*m_node.validation_signals, &peerman};
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

    BOOST_REQUIRE(m_node.chainman->ProcessNewBlock(
        std::make_shared<const CBlock>(child), /*force_processing=*/true,
        /*min_pow_checked=*/true, nullptr));
    BOOST_REQUIRE(PeermanWaitFor([&] {
        LOCK(::cs_main);
        const CBlockIndex* idx{
            m_node.chainman->m_blockman.LookupBlockIndex(child_hash)};
        return idx != nullptr &&
               (idx->nStatus & BLOCK_EXACT_REPLAY_VERIFIED) != 0 &&
               m_node.chainman->ActiveChain().Contains(idx);
    }));
    // generate/submitblock call ProcessNewBlock only. ProcessNewBlockFinished
    // must gossip via RelayLocalExactReplayAttestation (same helper as
    // ProcessBlockSync used to inline).
    BOOST_REQUIRE(PeermanWaitFor(
        [&] { return HasQueuedMessageType(peer, NetMsgType::MMATTEST); }));
    BOOST_CHECK(node::matmul_trusted::HasQuorum(child_hash, parent->nHeight + 1));
    connman.FlushSendBuffer(peer);
    BOOST_CHECK(!HasQueuedMessageType(peer, NetMsgType::MMATTEST));

    peerman.PersistExactReplayVerdictAndRelayForTest(child_hash);
    BOOST_REQUIRE(PeermanWaitFor(
        [&] { return HasQueuedMessageType(peer, NetMsgType::MMATTEST); }));
    BOOST_CHECK(node::matmul_trusted::HasQuorum(child_hash, parent->nHeight + 1));

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

// IBD miners scanning history must not pull MMATTEST off the signer uplink.
// Consecutive historical_not_served GETMMATTEST disconnects and 24h-bans.
BOOST_AUTO_TEST_CASE(getmmattest_historical_scan_ignored_then_banned)
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
    // GetMmAttestIsLiveWindow is height + 16 >= tip. A genesis-only
    // fixture has no historical height (0+16 >= 0). Mine past the live
    // window before activating Profile-1 so the probe is historical_not_served
    // rather than not_profile1 (ActivateRcAtTip would make ancestors
    // not_profile1).
    {
        const int need{node::matmul_trusted::SIGNER_GETMMATTEST_SERVE_WINDOW + 2};
        while (WITH_LOCK(::cs_main, return m_node.chainman->ActiveHeight()) <
               need) {
            const CBlockIndex* cur{
                WITH_LOCK(::cs_main, return m_node.chainman->ActiveTip())};
            BOOST_REQUIRE(cur != nullptr);
            mineBlock(m_node, std::chrono::seconds{cur->GetBlockTime() + 1});
        }
        NeutralizeUnconnectedHeaders(*Assert(m_node.chainman));
        tip = WITH_LOCK(::cs_main, return m_node.chainman->ActiveChain().Tip());
        BOOST_REQUIRE(tip != nullptr);
        BOOST_REQUIRE_GE(
            tip->nHeight, node::matmul_trusted::SIGNER_GETMMATTEST_SERVE_WINDOW + 1);
    }
    SetMockTime(std::chrono::seconds{tip->GetBlockTime() + 1});
    // Profile-1 from genesis so a mid-chain IBD probe is attestation-active
    // and still outside the live GETMMATTEST window.
    consensus.nMatMulV4Height = 0;
    consensus.nMatMulBMX4CHeight = 0;
    consensus.nMatMulDRLTHeight = std::numeric_limits<int32_t>::max();
    consensus.nMatMulRCHeight = 0;
    consensus.nMatMulRCCoupledHeight = std::numeric_limits<int32_t>::max();
    peerman.SetBestBlock(tip->nHeight, std::chrono::seconds{tip->GetBlockTime()});
    BOOST_REQUIRE(consensus.IsMatMulTrustedReplayAttestationActive(0));
    BOOST_REQUIRE(consensus.IsMatMulTrustedReplayAttestationActive(tip->nHeight));

    const int32_t historical_height{std::max(
        0, tip->nHeight - node::matmul_trusted::SIGNER_GETMMATTEST_SERVE_WINDOW -
               1)};
    const CBlockIndex* historical{
        WITH_LOCK(::cs_main, return tip->GetAncestor(historical_height))};
    BOOST_REQUIRE(historical != nullptr);
    BOOST_REQUIRE(m_node.chainman->ActiveChain().Contains(historical));
    BOOST_REQUIRE(!node::matmul_trusted::GetMmAttestIsLiveWindow(
        historical_height, tip->nHeight));
    const uint256 historical_hash{historical->GetBlockHash()};

    const ServiceFlags miner_services{ServiceFlags(NODE_NETWORK | NODE_WITNESS)};
    const CService public_addr{PeermanPublicService()};
    BOOST_REQUIRE(!public_addr.IsLocal());
    CNode scanner{/*id=*/404,
                  /*sock=*/nullptr,
                  CAddress{public_addr, NODE_NETWORK},
                  /*nKeyedNetGroupIn=*/0x71,
                  /*nLocalHostNonceIn=*/0,
                  CAddress{},
                  /*addrNameIn=*/"historical-ibd-scanner",
                  ConnectionType::INBOUND,
                  /*inbound_onion=*/false,
                  /*network_key=*/0};
    BOOST_REQUIRE(!scanner.addr.IsLocal());
    connman.Handshake(scanner, /*successfully_connected=*/true, miner_services,
                      miner_services, PROTOCOL_VERSION, /*relay_txs=*/true);
    connman.AddTestNode(scanner);
    connman.FlushSendBuffer(scanner);
    BOOST_CHECK(peerman.SendMessages(&scanner));
    connman.FlushSendBuffer(scanner);
    struct FinalizeScanner {
        ConnmanTestMsg& connman;
        PeerManager& peerman;
        BanMan* banman;
        CNode& node;
        ~FinalizeScanner()
        {
            peerman.FinalizeNode(node);
            connman.RemoveTestNode(node);
            if (banman) banman->Unban(node.addr);
        }
    } finalize{connman, peerman, m_node.banman.get(), scanner};

    scanner.fPauseSend = false;
    BOOST_REQUIRE(connman.ReceiveMsgFrom(
        scanner, NetMsg::Make(NetMsgType::GETMMATTEST, historical_hash)));
    scanner.fPauseSend = false;
    (void)connman.ProcessMessagesOnce(scanner);
    BOOST_CHECK(!HasQueuedMessageType(scanner, NetMsgType::MMATTEST));
    BOOST_CHECK(!scanner.fDisconnect);
    connman.FlushSendBuffer(scanner);

    for (int i = 1; i < node::matmul_trusted::GETMMATTEST_HAMMER_BAN_AFTER; ++i) {
        scanner.fPauseSend = false;
        BOOST_REQUIRE(connman.ReceiveMsgFrom(
            scanner, NetMsg::Make(NetMsgType::GETMMATTEST, historical_hash)));
        scanner.fPauseSend = false;
        (void)connman.ProcessMessagesOnce(scanner);
        BOOST_CHECK(!HasQueuedMessageType(scanner, NetMsgType::MMATTEST));
        if (i + 1 < node::matmul_trusted::GETMMATTEST_HAMMER_BAN_AFTER) {
            BOOST_CHECK(!scanner.fDisconnect);
        }
        connman.FlushSendBuffer(scanner);
    }
    BOOST_CHECK(scanner.fDisconnect);
    BOOST_REQUIRE(m_node.banman);
    BOOST_CHECK(m_node.banman->IsBanned(scanner.addr));
    banmap_t bans;
    m_node.banman->GetBanned(bans);
    BOOST_REQUIRE(!bans.empty());
    const int64_t remaining{bans.begin()->second.nBanUntil - GetTime()};
    BOOST_CHECK_GE(remaining, DEFAULT_MISBEHAVING_BANTIME - 5);
    BOOST_CHECK_LE(remaining, DEFAULT_MISBEHAVING_BANTIME);
}

static CBlockIndex* MakePeermanHeaderChild(ChainstateManager& chainman,
                                           const CBlockIndex& prev,
                                           unsigned int tag)
{
    CBlock block;
    block.SetNull();
    block.hashPrevBlock = prev.GetBlockHash();
    block.hashMerkleRoot = uint256::FromHex(
        std::string(62, '0') + strprintf("%02x", tag & 0xff)).value();
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
}

static std::unique_ptr<CNode> MakeOutboundConsensusPeer(NodeId id, int keyed)
{
    return std::make_unique<CNode>(
        id, /*sock=*/nullptr, CAddress{},
        static_cast<uint64_t>(keyed), /*nLocalHostNonceIn=*/0,
        CAddress{}, strprintf("hdr-sync-%d", id),
        ConnectionType::OUTBOUND_FULL_RELAY,
        /*inbound_onion=*/false, /*network_key=*/0);
}

BOOST_AUTO_TEST_CASE(stale_tip_with_inflight_and_forty_peers_sends_getheaders)
{
    // Live shape: tip stale >24h, nSyncStarted != 0, inflight non-empty,
    // 40 peers advertising above tip. F1: getheaders IS sent.
    LOCK(NetEventsInterface::g_msgproc_mutex);
    ResetSharedPeermanFixture(m_node);
    ChainstateManager& chainman{*Assert(m_node.chainman)};
    PeerManager& peerman{*Assert(m_node.peerman)};
    ConnmanTestMsg& connman{static_cast<ConnmanTestMsg&>(*m_node.connman)};
    const CBlockIndex* tip{
        WITH_LOCK(::cs_main, return chainman.ActiveChain().Tip())};
    BOOST_REQUIRE(tip != nullptr);
    SetMockTime(std::chrono::seconds{tip->GetBlockTime() + 55 * 3600});
    BOOST_REQUIRE(!chainman.IsInitialBlockDownload());

    CBlockIndex* hole{MakePeermanHeaderChild(chainman, *tip, 0xc1)};
    const ServiceFlags services{ServiceFlags(
        NODE_NETWORK | NODE_WITNESS | NODE_MATMUL_CONSENSUS)};

    CNode staller{/*id=*/900, /*sock=*/nullptr, CAddress{},
                  /*nKeyedNetGroupIn=*/900, /*nLocalHostNonceIn=*/0,
                  CAddress{}, /*addrNameIn=*/"stale-staller",
                  ConnectionType::OUTBOUND_FULL_RELAY,
                  /*inbound_onion=*/false, /*network_key=*/0};
    connman.Handshake(staller, /*successfully_connected=*/true, services,
                      services, PROTOCOL_VERSION, /*relay_txs=*/true,
                      /*starting_height=*/tip->nHeight + 1);
    connman.FlushSendBuffer(staller);
    {
        std::vector<CBlock> hdrs{CBlock{hole->GetBlockHeader()}};
        BOOST_REQUIRE(connman.ReceiveMsgFrom(
            staller, NetMsg::Make(NetMsgType::HEADERS, TX_WITH_WITNESS(hdrs))));
        staller.fPauseSend = false;
        (void)connman.ProcessMessagesOnce(staller);
    }
    BOOST_CHECK(peerman.SendMessages(&staller));
    CNodeStateStats staller_stats;
    BOOST_REQUIRE(peerman.GetNodeStateStats(staller.GetId(), staller_stats));
    BOOST_REQUIRE_MESSAGE(!staller_stats.vHeightInFlight.empty(),
                          "test setup: inflight must be non-empty");
    BOOST_REQUIRE_NE(staller_stats.m_total_headers_sync_peer_count, 0);

    constexpr int kPeers{40};
    std::vector<std::unique_ptr<CNode>> peers;
    peers.reserve(kPeers);
    for (int i = 0; i < kPeers; ++i) {
        peers.push_back(MakeOutboundConsensusPeer(1000 + i, 1000 + i));
        connman.Handshake(*peers.back(), /*successfully_connected=*/true,
                          services, services, PROTOCOL_VERSION,
                          /*relay_txs=*/true,
                          /*starting_height=*/199328);
        connman.FlushSendBuffer(*peers.back());
    }
    SetMockTime(std::chrono::seconds{GetTime() + 180});
    int sent{0};
    for (auto& peer : peers) {
        BOOST_CHECK(peerman.SendMessages(peer.get()));
        if (HasQueuedMessageType(*peer, NetMsgType::GETHEADERS)) ++sent;
    }
    BOOST_REQUIRE_MESSAGE(sent > 0,
                          "F1: stale tip + nSyncStarted!=0 + inflight + 40 "
                          "peers above tip must still send getheaders");

    // GETHEADERS is still in the V1 transport (sock=null optimistic write).
    // Drain it before ReceiveMsgFrom reuses the same transport for HEADERS.
    connman.FlushSendBuffer(*peers.front());
    peers.front()->fPauseSend = false;

    std::vector<CBlockIndex*> suffix;
    const CBlockIndex* walk{tip};
    for (unsigned int tag = 0xd0; tag < 0xd0 + 6; ++tag) {
        suffix.push_back(MakePeermanHeaderChild(chainman, *walk, tag));
        walk = suffix.back();
    }
    std::vector<CBlock> hdrs;
    for (CBlockIndex* idx : suffix) hdrs.emplace_back(idx->GetBlockHeader());
    BOOST_REQUIRE(connman.ReceiveMsgFrom(
        *peers.front(),
        NetMsg::Make(NetMsgType::HEADERS, TX_WITH_WITNESS(hdrs))));
    peers.front()->fPauseSend = false;
    (void)connman.ProcessMessagesOnce(*peers.front());
    CNodeStateStats learned;
    BOOST_REQUIRE(peerman.GetNodeStateStats(peers.front()->GetId(), learned));
    BOOST_CHECK_EQUAL(learned.nSyncHeight, tip->nHeight + 6);
    BOOST_CHECK_EQUAL(
        WITH_LOCK(::cs_main, return chainman.m_best_header->nHeight),
        tip->nHeight + 6);

    peerman.FinalizeNode(staller);
    for (auto& peer : peers) peerman.FinalizeNode(*peer);
    NeutralizeUnconnectedHeaders(chainman);
    peerman.ResetMatMulVerifyAdmissionForTest();
}

BOOST_AUTO_TEST_CASE(sixty_two_preferred_peers_null_best_known_probe_fires)
{
    // Regression guard for the inverted hatch: 62 preferred peers, all
    // best_known == nullptr, must still probe. This is the single most
    // important test in 0.34.1.
    LOCK(NetEventsInterface::g_msgproc_mutex);
    ResetSharedPeermanFixture(m_node);
    ChainstateManager& chainman{*Assert(m_node.chainman)};
    PeerManager& peerman{*Assert(m_node.peerman)};
    ConnmanTestMsg& connman{static_cast<ConnmanTestMsg&>(*m_node.connman)};
    const CBlockIndex* tip{
        WITH_LOCK(::cs_main, return chainman.ActiveChain().Tip())};
    BOOST_REQUIRE(tip != nullptr);
    SetMockTime(std::chrono::seconds{tip->GetBlockTime() + 55 * 3600});
    BOOST_REQUIRE(!chainman.IsInitialBlockDownload());

    const ServiceFlags services{ServiceFlags(
        NODE_NETWORK | NODE_WITNESS | NODE_MATMUL_CONSENSUS)};
    constexpr int kPreferred{62};
    std::vector<std::unique_ptr<CNode>> peers;
    peers.reserve(kPreferred);
    for (int i = 0; i < kPreferred; ++i) {
        peers.push_back(MakeOutboundConsensusPeer(2000 + i, 2000 + i));
        connman.Handshake(*peers.back(), /*successfully_connected=*/true,
                          services, services, PROTOCOL_VERSION,
                          /*relay_txs=*/true,
                          /*starting_height=*/199328);
        connman.FlushSendBuffer(*peers.back());
    }
    CNodeStateStats first;
    BOOST_REQUIRE(peerman.GetNodeStateStats(peers.front()->GetId(), first));
    BOOST_REQUIRE_GE(first.m_total_preferred_download_peer_count, kPreferred);
    BOOST_CHECK_EQUAL(first.nSyncHeight, -1);

    SetMockTime(std::chrono::seconds{GetTime() + 180});
    int probed{0};
    int still_null{0};
    for (auto& peer : peers) {
        CNodeStateStats before;
        BOOST_REQUIRE(peerman.GetNodeStateStats(peer->GetId(), before));
        if (before.nSyncHeight < 0) ++still_null;
        BOOST_CHECK(peerman.SendMessages(peer.get()));
        if (HasQueuedMessageType(*peer, NetMsgType::GETHEADERS)) ++probed;
    }
    BOOST_REQUIRE_EQUAL(still_null, kPreferred);
    BOOST_REQUIRE_MESSAGE(probed > 0,
                          "inverted-hatch regression: 62 preferred peers with "
                          "best_known null must still fire the getheaders probe");

    for (auto& peer : peers) peerman.FinalizeNode(*peer);
    peerman.ResetMatMulVerifyAdmissionForTest();
}

BOOST_AUTO_TEST_CASE(pindex_last_common_behind_tip_advances_and_does_not_rerequest)
{
    LOCK(NetEventsInterface::g_msgproc_mutex);
    ResetSharedPeermanFixture(m_node);
    ChainstateManager& chainman{*Assert(m_node.chainman)};
    PeerManager& peerman{*Assert(m_node.peerman)};
    ConnmanTestMsg& connman{static_cast<ConnmanTestMsg&>(*m_node.connman)};
    const CBlockIndex* tip{
        WITH_LOCK(::cs_main, return chainman.ActiveChain().Tip())};
    BOOST_REQUIRE(tip != nullptr);
    if (tip->pprev == nullptr) {
        mineBlock(m_node, std::chrono::seconds{tip->GetBlockTime() + 1});
        tip = WITH_LOCK(::cs_main, return chainman.ActiveChain().Tip());
        BOOST_REQUIRE(tip != nullptr);
        peerman.SetBestBlock(tip->nHeight,
                             std::chrono::seconds{tip->GetBlockTime()});
    }
    BOOST_REQUIRE(tip->pprev != nullptr);
    SetMockTime(std::chrono::seconds{tip->GetBlockTime() + 3600});

    CBlock competing;
    competing.SetNull();
    competing.hashPrevBlock = tip->pprev->GetBlockHash();
    competing.nTime = tip->pprev->GetBlockTime() + 2;
    competing.nBits = tip->nBits;
    competing.nVersion = VERSIONBITS_TOP_BITS;
    competing.hashMerkleRoot = uint256::FromHex(std::string(64, 'c')).value();
    BOOST_REQUIRE(MineHeaderForConsensus(
        competing, tip->pprev->nHeight + 1, chainman.GetConsensus(), 5'000'000,
        tip->pprev->GetMedianTimePast()));
    BlockValidationState state;
    BOOST_REQUIRE_MESSAGE(chainman.ProcessNewBlockHeaders(
        {{competing.GetBlockHeader()}}, /*min_pow_checked=*/true, state),
        state.ToString());
    const uint256 twin_hash{competing.GetHash()};

    const ServiceFlags services{ServiceFlags(
        NODE_NETWORK | NODE_WITNESS | NODE_MATMUL_CONSENSUS)};
    CNode peer{/*id=*/3000, /*sock=*/nullptr, CAddress{},
               /*nKeyedNetGroupIn=*/3000, /*nLocalHostNonceIn=*/0,
               CAddress{}, /*addrNameIn=*/"last-common-twin",
               ConnectionType::OUTBOUND_FULL_RELAY,
               /*inbound_onion=*/false, /*network_key=*/0};
    connman.Handshake(peer, /*successfully_connected=*/true, services, services,
                      PROTOCOL_VERSION, /*relay_txs=*/true,
                      /*starting_height=*/tip->nHeight);
    connman.FlushSendBuffer(peer);
    std::vector<CBlock> hdrs{CBlock{competing.GetBlockHeader()}};
    BOOST_REQUIRE(connman.ReceiveMsgFrom(
        peer, NetMsg::Make(NetMsgType::HEADERS, TX_WITH_WITNESS(hdrs))));
    peer.fPauseSend = false;
    (void)connman.ProcessMessagesOnce(peer);

    BOOST_CHECK(peerman.SendMessages(&peer));
    CNodeStateStats after_first;
    BOOST_REQUIRE(peerman.GetNodeStateStats(peer.GetId(), after_first));
    BOOST_CHECK_GE(after_first.nCommonHeight, tip->nHeight);
    const size_t first_twin_getdata{CountQueuedGetDataForHash(peer, twin_hash)};
    connman.FlushSendBuffer(peer);
    BOOST_CHECK(peerman.SendMessages(&peer));
    CNodeStateStats after_second;
    BOOST_REQUIRE(peerman.GetNodeStateStats(peer.GetId(), after_second));
    BOOST_CHECK_GE(after_second.nCommonHeight, tip->nHeight);
    BOOST_CHECK_EQUAL(CountQueuedGetDataForHash(peer, twin_hash), 0U);
    BOOST_CHECK_EQUAL(first_twin_getdata, 0U);

    peerman.FinalizeNode(peer);
    NeutralizeUnconnectedHeaders(chainman);
    peerman.ResetMatMulVerifyAdmissionForTest();
}

BOOST_AUTO_TEST_CASE(live_shape_199300_converges_toward_199328)
{
    // VERSION heights are the live numbers (199301 / 199303 / 199328).
    // The local chain is the regtest tip standing in for 199300; we feed
    // +1 / +3 / +28 real headers and assert convergence to the best
    // advertised suffix.
    LOCK(NetEventsInterface::g_msgproc_mutex);
    ResetSharedPeermanFixture(m_node);
    ChainstateManager& chainman{*Assert(m_node.chainman)};
    PeerManager& peerman{*Assert(m_node.peerman)};
    ConnmanTestMsg& connman{static_cast<ConnmanTestMsg&>(*m_node.connman)};
    const CBlockIndex* local_199300{
        WITH_LOCK(::cs_main, return chainman.ActiveChain().Tip())};
    BOOST_REQUIRE(local_199300 != nullptr);
    SetMockTime(std::chrono::seconds{local_199300->GetBlockTime() + 55 * 3600});

    std::vector<CBlockIndex*> ext;
    const CBlockIndex* walk{local_199300};
    for (int i = 0; i < 28; ++i) {
        ext.push_back(MakePeermanHeaderChild(chainman, *walk, 0xe0 + i));
        walk = ext.back();
    }
    BOOST_REQUIRE_EQUAL(ext.size(), 28U);

    const ServiceFlags services{ServiceFlags(
        NODE_NETWORK | NODE_WITNESS | NODE_MATMUL_CONSENSUS)};
    auto handshake = [&](CNode& node, int32_t starting) {
        connman.Handshake(node, /*successfully_connected=*/true, services,
                          services, PROTOCOL_VERSION, /*relay_txs=*/true,
                          starting);
        connman.FlushSendBuffer(node);
    };
    CNode p301{/*id=*/4001, /*sock=*/nullptr, CAddress{}, 4001, 0, CAddress{},
               "live-199301", ConnectionType::OUTBOUND_FULL_RELAY, false, 0};
    CNode p303{/*id=*/4003, /*sock=*/nullptr, CAddress{}, 4003, 0, CAddress{},
               "live-199303", ConnectionType::OUTBOUND_FULL_RELAY, false, 0};
    CNode p328{/*id=*/4028, /*sock=*/nullptr, CAddress{}, 4028, 0, CAddress{},
               "live-199328", ConnectionType::OUTBOUND_FULL_RELAY, false, 0};
    handshake(p301, 199301);
    handshake(p303, 199303);
    handshake(p328, 199328);

    SetMockTime(std::chrono::seconds{GetTime() + 180});
    BOOST_CHECK(peerman.SendMessages(&p328));
    BOOST_CHECK(HasQueuedMessageType(p328, NetMsgType::GETHEADERS));
    connman.FlushSendBuffer(p328);

    auto feed = [&](CNode& node, size_t n) {
        std::vector<CBlock> hdrs;
        hdrs.reserve(n);
        for (size_t i = 0; i < n; ++i) hdrs.emplace_back(ext[i]->GetBlockHeader());
        BOOST_REQUIRE(connman.ReceiveMsgFrom(
            node, NetMsg::Make(NetMsgType::HEADERS, TX_WITH_WITNESS(hdrs))));
        node.fPauseSend = false;
        (void)connman.ProcessMessagesOnce(node);
    };
    feed(p301, 1);
    feed(p303, 3);
    feed(p328, 28);

    CNodeStateStats s301, s303, s328;
    BOOST_REQUIRE(peerman.GetNodeStateStats(p301.GetId(), s301));
    BOOST_REQUIRE(peerman.GetNodeStateStats(p303.GetId(), s303));
    BOOST_REQUIRE(peerman.GetNodeStateStats(p328.GetId(), s328));
    BOOST_CHECK_EQUAL(s301.nSyncHeight, local_199300->nHeight + 1);
    BOOST_CHECK_EQUAL(s303.nSyncHeight, local_199300->nHeight + 3);
    BOOST_CHECK_EQUAL(s328.nSyncHeight, local_199300->nHeight + 28);
    BOOST_CHECK_EQUAL(
        WITH_LOCK(::cs_main, return chainman.m_best_header->nHeight),
        local_199300->nHeight + 28);

    peerman.FinalizeNode(p301);
    peerman.FinalizeNode(p303);
    peerman.FinalizeNode(p328);
    NeutralizeUnconnectedHeaders(chainman);
    peerman.ResetMatMulVerifyAdmissionForTest();
}

// PR 124 follow-up / MendeMatthias 2026-08-27: GETHEADERS and GETBLOCKS are
// inbound SERVES, not ingest. An authority-mode node must answer GETHEADERS
// from a non-authority inbound peer with a non-empty HEADERS message.
// Assert by queued message bytes/count, not LogDebug("sending getheaders").
BOOST_AUTO_TEST_CASE(authority_mode_serves_getheaders_to_inbound_non_authority)
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

    const CBlockIndex* start_tip{
        WITH_LOCK(::cs_main, return m_node.chainman->ActiveChain().Tip())};
    BOOST_REQUIRE(start_tip != nullptr);
    for (int i = 0; i < 3; ++i) {
        mineBlock(m_node, std::chrono::seconds{start_tip->GetBlockTime() + 1 + i});
    }
    {
        LOCK(::cs_main);
        CBlockIndex* tip{const_cast<CBlockIndex*>(m_node.chainman->ActiveTip())};
        BOOST_REQUIRE(tip != nullptr);
        for (CBlockIndex* walk{tip}; walk != nullptr; walk = walk->pprev) {
            walk->nAuthenticatedChainWork = walk->nChainWork;
        }
    }

    ConnmanTestMsg& connman = static_cast<ConnmanTestMsg&>(*m_node.connman);
    PeerManager& peerman = *m_node.peerman;
    const ServiceFlags ordinary_services{ServiceFlags(NODE_NETWORK | NODE_WITNESS)};
    CNode inbound{/*id=*/410,
                  /*sock=*/nullptr,
                  CAddress{PeermanTestService(0x2a00007f), NODE_NETWORK},
                  /*nKeyedNetGroupIn=*/0x2a,
                  /*nLocalHostNonceIn=*/0,
                  CAddress{},
                  /*addrNameIn=*/"inbound-bootstrap",
                  ConnectionType::INBOUND,
                  /*inbound_onion=*/false,
                  /*network_key=*/0};
    connman.Handshake(inbound, /*successfully_connected=*/true, ordinary_services,
                      ordinary_services, PROTOCOL_VERSION, /*relay_txs=*/true);
    connman.AddTestNode(inbound);
    connman.FlushSendBuffer(inbound);
    struct FinalizeInbound {
        ConnmanTestMsg& connman;
        PeerManager& peerman;
        CNode& node;
        ~FinalizeInbound()
        {
            peerman.FinalizeNode(node);
            connman.RemoveTestNode(node);
        }
    } finalize{connman, peerman, inbound};

    const uint256 genesis_hash{WITH_LOCK(
        ::cs_main, return m_node.chainman->ActiveChain()[0]->GetBlockHash())};
    CBlockLocator locator{std::vector<uint256>{genesis_hash}};
    inbound.fPauseSend = false;
    BOOST_REQUIRE(connman.ReceiveMsgFrom(
        inbound, NetMsg::Make(NetMsgType::GETHEADERS, locator, uint256{})));
    inbound.fPauseSend = false;
    (void)connman.ProcessMessagesOnce(inbound);

    BOOST_CHECK_GE(CountQueuedMessageType(inbound, NetMsgType::HEADERS), 1U);
    BOOST_REQUIRE_MESSAGE(
        CountQueuedHeaderBlocks(inbound) > 0,
        "authority-mode node must serve a non-empty HEADERS reply to inbound "
        "GETHEADERS; dropping GETHEADERS as ingest is the 199300 stall "
        "(PR 124 / MendeMatthias)");
}

BOOST_AUTO_TEST_CASE(best_header_below_tip_rerequests_headers_and_converges)
{
    // Live 0.34.3 macpro2: blocks=199310, headers=199024. PreferTrustAdjusted
    // ranked an authenticated ancestor above the connected tip, so locators
    // started at 199023 and never asked for tip+1. This case rewinds
    // m_best_header below the tip, asserts SendMessages re-establishes it,
    // sends getheaders, and learns a peer suffix above the tip.
    LOCK(NetEventsInterface::g_msgproc_mutex);
    ResetSharedPeermanFixture(m_node);
    ChainstateManager& chainman{*Assert(m_node.chainman)};
    PeerManager& peerman{*Assert(m_node.peerman)};
    ConnmanTestMsg& connman{static_cast<ConnmanTestMsg&>(*m_node.connman)};
    const CBlockIndex* tip{
        WITH_LOCK(::cs_main, return chainman.ActiveChain().Tip())};
    BOOST_REQUIRE(tip != nullptr);
    if (tip->pprev == nullptr) {
        mineBlock(m_node, std::chrono::seconds{tip->GetBlockTime() + 1});
        tip = WITH_LOCK(::cs_main, return chainman.ActiveChain().Tip());
        BOOST_REQUIRE(tip != nullptr);
        peerman.SetBestBlock(tip->nHeight,
                             std::chrono::seconds{tip->GetBlockTime()});
    }
    BOOST_REQUIRE(tip->pprev != nullptr);

    std::vector<CBlockIndex*> suffix;
    const CBlockIndex* walk{tip};
    for (unsigned int tag = 0xa0; tag < 0xa0 + 6; ++tag) {
        suffix.push_back(MakePeermanHeaderChild(chainman, *walk, tag));
        walk = suffix.back();
    }
    BOOST_REQUIRE_EQUAL(suffix.size(), 6U);

    WITH_LOCK(::cs_main, {
        chainman.SetBestHeader(const_cast<CBlockIndex*>(tip->pprev));
        BOOST_CHECK_LT(chainman.m_best_header->nHeight, tip->nHeight);
        chainman.EnsureBestHeaderNotBehindConnectedTip();
        BOOST_CHECK_EQUAL(chainman.m_best_header->nHeight, tip->nHeight);
        BOOST_CHECK_EQUAL(chainman.m_best_header, tip);
        chainman.SetBestHeader(const_cast<CBlockIndex*>(tip->pprev));
    });

    const ServiceFlags services{ServiceFlags(
        NODE_NETWORK | NODE_WITNESS | NODE_MATMUL_CONSENSUS)};
    CNode peer{/*id=*/5100, /*sock=*/nullptr, CAddress{},
               /*nKeyedNetGroupIn=*/5100, /*nLocalHostNonceIn=*/0,
               CAddress{}, /*addrNameIn=*/"best-header-behind-tip",
               ConnectionType::OUTBOUND_FULL_RELAY,
               /*inbound_onion=*/false, /*network_key=*/0};
    connman.Handshake(peer, /*successfully_connected=*/true, services, services,
                      PROTOCOL_VERSION, /*relay_txs=*/true,
                      /*starting_height=*/tip->nHeight + 6);
    connman.FlushSendBuffer(peer);
    // Handshake / version processing may stamp m_last_getheaders_timestamp.
    // Wait out HEADERS_RESPONSE_TIME (2min) like the F1 probe tests.
    SetMockTime(std::chrono::seconds{GetTime() + 180});

    BOOST_CHECK(peerman.SendMessages(&peer));
    BOOST_REQUIRE_MESSAGE(HasQueuedMessageType(peer, NetMsgType::GETHEADERS),
                          "best-header below the connected tip must resume "
                          "sending getheaders");
    BOOST_CHECK_GE(
        WITH_LOCK(::cs_main, return chainman.m_best_header->nHeight),
        tip->nHeight);

    connman.FlushSendBuffer(peer);
    peer.fPauseSend = false;
    std::vector<CBlock> hdrs;
    for (CBlockIndex* idx : suffix) hdrs.emplace_back(idx->GetBlockHeader());
    BOOST_REQUIRE(connman.ReceiveMsgFrom(
        peer, NetMsg::Make(NetMsgType::HEADERS, TX_WITH_WITNESS(hdrs))));
    peer.fPauseSend = false;
    (void)connman.ProcessMessagesOnce(peer);

    CNodeStateStats learned;
    BOOST_REQUIRE(peerman.GetNodeStateStats(peer.GetId(), learned));
    BOOST_CHECK_EQUAL(learned.nSyncHeight, tip->nHeight + 6);
    BOOST_CHECK_GE(
        WITH_LOCK(::cs_main, return chainman.m_best_header->nHeight),
        tip->nHeight);

    peerman.FinalizeNode(peer);
    NeutralizeUnconnectedHeaders(chainman);
    peerman.ResetMatMulVerifyAdmissionForTest();
}

BOOST_AUTO_TEST_CASE(heavier_competing_fork_probes_and_getdata_past_short_reorg)
{
    // Live 0.34.4 macpro2: tip 199310 on 8b5da5a5, headers-only fork from
    // 199294 (33c834f8) at the 72-block unauth lead cap, peer VERSION 199523.
    // HeaderSyncMustProbe treated BestKnown 199382 as "ahead" (zero
    // getheaders). FindNextBlocksToDownload skipped competing_not_active_
    // tip_chain (LCA depth 16 > short-reorg 6). CanDirectFetch was false
    // (tip ~91h stale). reconsiderblock 33c834f8 could not connect bodies
    // that were never requested.
    LOCK(NetEventsInterface::g_msgproc_mutex);
    node::matmul_trusted::ResetForTest();
    ResetSharedPeermanFixture(m_node);
    ChainstateManager& chainman{*Assert(m_node.chainman)};
    PeerManager& peerman{*Assert(m_node.peerman)};
    ConnmanTestMsg& connman{static_cast<ConnmanTestMsg&>(*m_node.connman)};

    const CBlockIndex* fork_root{
        WITH_LOCK(::cs_main, return chainman.ActiveChain().Tip())};
    BOOST_REQUIRE(fork_root != nullptr);
    for (int i = 0; i < 8; ++i) {
        mineBlock(m_node, std::chrono::seconds{fork_root->GetBlockTime() + 1 + i});
    }
    const CBlockIndex* tip{
        WITH_LOCK(::cs_main, return chainman.ActiveChain().Tip())};
    BOOST_REQUIRE(tip != nullptr);
    BOOST_REQUIRE_EQUAL(tip->nHeight, fork_root->nHeight + 8);
    BOOST_REQUIRE_EQUAL(tip->GetAncestor(fork_root->nHeight), fork_root);
    {
        LOCK(::cs_main);
        for (CBlockIndex* walk{const_cast<CBlockIndex*>(tip)}; walk != nullptr;
             walk = walk->pprev) {
            walk->nAuthenticatedChainWork = walk->nChainWork;
        }
        chainman.SetBestHeader(const_cast<CBlockIndex*>(tip));
        peerman.SetBestBlock(tip->nHeight,
                             std::chrono::seconds{tip->GetBlockTime()});
    }

    std::vector<CBlockIndex*> fork;
    const CBlockIndex* walk{fork_root};
    for (unsigned int tag = 0xb0; tag < 0xb0 + 16; ++tag) {
        fork.push_back(MakePeermanHeaderChild(chainman, *walk, tag));
        walk = fork.back();
    }
    BOOST_REQUIRE_EQUAL(fork.size(), 16U);
    BOOST_REQUIRE_GT(fork.back()->nHeight, tip->nHeight);
    BOOST_CHECK(WITH_LOCK(::cs_main, return fork.back()->GetAncestor(tip->nHeight) != tip));
    BOOST_CHECK(WITH_LOCK(::cs_main, return fork.back()->nChainWork > tip->nChainWork));
    BOOST_CHECK_GT(tip->nHeight - fork_root->nHeight, 6);

    // Tip older than CanDirectFetch window (20 * spacing). GETDATA must
    // come from FindNextBlocksToDownload, not HeadersDirectFetchBlocks.
    SetMockTime(std::chrono::seconds{tip->GetBlockTime() + 55 * 3600});
    BOOST_REQUIRE(!chainman.IsInitialBlockDownload());

    const ServiceFlags services{ServiceFlags(
        NODE_NETWORK | NODE_WITNESS | NODE_MATMUL_CONSENSUS)};
    CNode peer{/*id=*/5200, /*sock=*/nullptr, CAddress{},
               /*nKeyedNetGroupIn=*/5200, /*nLocalHostNonceIn=*/0,
               CAddress{}, /*addrNameIn=*/"heavier-competing-fork",
               ConnectionType::OUTBOUND_FULL_RELAY,
               /*inbound_onion=*/false, /*network_key=*/0};
    connman.Handshake(peer, /*successfully_connected=*/true, services, services,
                      PROTOCOL_VERSION, /*relay_txs=*/true,
                      /*starting_height=*/fork.back()->nHeight);
    connman.FlushSendBuffer(peer);

    std::vector<CBlock> hdrs;
    hdrs.reserve(fork.size());
    for (CBlockIndex* idx : fork) hdrs.emplace_back(idx->GetBlockHeader());
    BOOST_REQUIRE(connman.ReceiveMsgFrom(
        peer, NetMsg::Make(NetMsgType::HEADERS, TX_WITH_WITNESS(hdrs))));
    peer.fPauseSend = false;
    (void)connman.ProcessMessagesOnce(peer);
    connman.FlushSendBuffer(peer);

    CNodeStateStats learned;
    BOOST_REQUIRE(peerman.GetNodeStateStats(peer.GetId(), learned));
    BOOST_CHECK_EQUAL(learned.nSyncHeight, fork.back()->nHeight);

    SetMockTime(std::chrono::seconds{GetTime() + 180});
    BOOST_CHECK(peerman.SendMessages(&peer));
    BOOST_REQUIRE_MESSAGE(
        HasQueuedMessageType(peer, NetMsgType::GETHEADERS),
        "BestKnown on a heavier competing fork must not suppress getheaders");
    BOOST_REQUIRE_MESSAGE(
        CountQueuedGetDataForHash(peer, fork.front()->GetBlockHash()) > 0,
        "heavier competing fork past short-reorg depth must be GETDATA'd");

    peerman.FinalizeNode(peer);
    NeutralizeUnconnectedHeaders(chainman);
    peerman.ResetMatMulVerifyAdmissionForTest();
    node::matmul_trusted::ResetForTest();
}

BOOST_AUTO_TEST_CASE(heavier_competing_fork_n_plus_72_getdata_fork_child)
{
    // Operator 2026-08-28: tip N, accepted BestKnown N+72 forking at N-k
    // (live k=14, peer 275 synH=199384 vs tip 199312). lowest_missing is
    // the fork child; GETDATA must go out even past short-reorg depth 6.
    LOCK(NetEventsInterface::g_msgproc_mutex);
    node::matmul_trusted::ResetForTest();
    ResetSharedPeermanFixture(m_node);
    ChainstateManager& chainman{*Assert(m_node.chainman)};
    PeerManager& peerman{*Assert(m_node.peerman)};
    ConnmanTestMsg& connman{static_cast<ConnmanTestMsg&>(*m_node.connman)};

    constexpr int k_below{14};
    constexpr int k_ahead{72};
    const CBlockIndex* fork_root{
        WITH_LOCK(::cs_main, return chainman.ActiveChain().Tip())};
    BOOST_REQUIRE(fork_root != nullptr);
    for (int i = 0; i < k_below; ++i) {
        mineBlock(m_node, std::chrono::seconds{fork_root->GetBlockTime() + 1 + i});
    }
    const CBlockIndex* tip{
        WITH_LOCK(::cs_main, return chainman.ActiveChain().Tip())};
    BOOST_REQUIRE(tip != nullptr);
    BOOST_REQUIRE_EQUAL(tip->nHeight, fork_root->nHeight + k_below);
    {
        LOCK(::cs_main);
        for (CBlockIndex* walk{const_cast<CBlockIndex*>(tip)}; walk != nullptr;
             walk = walk->pprev) {
            walk->nAuthenticatedChainWork = walk->nChainWork;
        }
        chainman.SetBestHeader(const_cast<CBlockIndex*>(tip));
        peerman.SetBestBlock(tip->nHeight,
                             std::chrono::seconds{tip->GetBlockTime()});
    }

    std::vector<CBlockIndex*> fork;
    const CBlockIndex* walk{fork_root};
    for (int i = 0; i < k_below + k_ahead; ++i) {
        fork.push_back(MakePeermanHeaderChild(chainman, *walk, 0xb0 + (i & 0xff)));
        walk = fork.back();
    }
    BOOST_REQUIRE_EQUAL(fork.size(), static_cast<size_t>(k_below + k_ahead));
    BOOST_REQUIRE_EQUAL(fork.back()->nHeight, tip->nHeight + k_ahead);
    BOOST_CHECK(WITH_LOCK(::cs_main, return fork.back()->GetAncestor(tip->nHeight) != tip));
    BOOST_CHECK(WITH_LOCK(::cs_main, return fork.back()->nChainWork > tip->nChainWork));

    SetMockTime(std::chrono::seconds{tip->GetBlockTime() + 55 * 3600});
    BOOST_REQUIRE(!chainman.IsInitialBlockDownload());

    const ServiceFlags services{ServiceFlags(
        NODE_NETWORK | NODE_WITNESS | NODE_MATMUL_CONSENSUS)};
    CNode peer{/*id=*/5400, /*sock=*/nullptr, CAddress{},
               /*nKeyedNetGroupIn=*/5400, /*nLocalHostNonceIn=*/0,
               CAddress{}, /*addrNameIn=*/"heavier-fork-n-plus-72",
               ConnectionType::OUTBOUND_FULL_RELAY,
               /*inbound_onion=*/false, /*network_key=*/0};
    connman.Handshake(peer, /*successfully_connected=*/true, services, services,
                      PROTOCOL_VERSION, /*relay_txs=*/true,
                      /*starting_height=*/fork.back()->nHeight);
    connman.FlushSendBuffer(peer);

    std::vector<CBlock> hdrs;
    hdrs.reserve(fork.size());
    for (CBlockIndex* idx : fork) hdrs.emplace_back(idx->GetBlockHeader());
    BOOST_REQUIRE(connman.ReceiveMsgFrom(
        peer, NetMsg::Make(NetMsgType::HEADERS, TX_WITH_WITNESS(hdrs))));
    peer.fPauseSend = false;
    (void)connman.ProcessMessagesOnce(peer);
    connman.FlushSendBuffer(peer);

    CNodeStateStats learned;
    BOOST_REQUIRE(peerman.GetNodeStateStats(peer.GetId(), learned));
    BOOST_CHECK_EQUAL(learned.nSyncHeight, fork.back()->nHeight);

    SetMockTime(std::chrono::seconds{GetTime() + 180});
    peer.fPauseSend = false;
    BOOST_CHECK(peerman.SendMessages(&peer));
    BOOST_REQUIRE_MESSAGE(
        CountQueuedGetDataForHash(peer, fork.front()->GetBlockHash()) > 0,
        "heavier competing fork N+72 forking at N-k must GETDATA the fork child");

    peerman.FinalizeNode(peer);
    NeutralizeUnconnectedHeaders(chainman);
    peerman.ResetMatMulVerifyAdmissionForTest();
    node::matmul_trusted::ResetForTest();
}

BOOST_AUTO_TEST_CASE(header_tower_seeds_best_known_without_duplicate_headers)
{
    // Live rtx6000 2026-08-29: buffer pool ready, deferred-replay gone, but
    // inflight=0 / block_recv=0. m_best_header=199801, 6 peers advertise
    // above tip, selector asked peer=29 at 199386 (already_at_peer_best).
    // Headers are already in the index — do not wait for a duplicate
    // HEADERS batch to set BestKnown.
    LOCK(NetEventsInterface::g_msgproc_mutex);
    node::matmul_trusted::ResetForTest();
    ResetSharedPeermanFixture(m_node);
    ChainstateManager& chainman{*Assert(m_node.chainman)};
    PeerManager& peerman{*Assert(m_node.peerman)};
    ConnmanTestMsg& connman{static_cast<ConnmanTestMsg&>(*m_node.connman)};

    const CBlockIndex* tip{
        WITH_LOCK(::cs_main, return chainman.ActiveChain().Tip())};
    BOOST_REQUIRE(tip != nullptr);
    constexpr int k_ahead{80};
    std::vector<CBlockIndex*> tower;
    const CBlockIndex* walk{tip};
    for (int i = 0; i < k_ahead; ++i) {
        tower.push_back(MakePeermanHeaderChild(chainman, *walk, 0xa0 + (i & 0xff)));
        walk = tower.back();
    }
    BOOST_REQUIRE_EQUAL(tower.size(), static_cast<size_t>(k_ahead));
    BOOST_REQUIRE_EQUAL(tower.back()->nHeight, tip->nHeight + k_ahead);
    {
        LOCK(::cs_main);
        chainman.SetBestHeader(tower.back());
        peerman.SetBestBlock(tip->nHeight,
                             std::chrono::seconds{tip->GetBlockTime()});
    }
    BOOST_CHECK(WITH_LOCK(::cs_main, {
        return chainman.m_best_header == tower.back() &&
               tower.back()->GetAncestor(tip->nHeight) == tip &&
               tower.back()->nChainWork > tip->nChainWork;
    }));

    SetMockTime(std::chrono::seconds{tip->GetBlockTime() + 55 * 3600});
    BOOST_REQUIRE(!chainman.IsInitialBlockDownload());

    const ServiceFlags services{ServiceFlags(
        NODE_NETWORK | NODE_WITNESS | NODE_MATMUL_CONSENSUS)};
    CNode at_tip{/*id=*/6100, /*sock=*/nullptr, CAddress{},
                 /*nKeyedNetGroupIn=*/6100, /*nLocalHostNonceIn=*/0,
                 CAddress{}, /*addrNameIn=*/"header-tower-at-tip",
                 ConnectionType::OUTBOUND_FULL_RELAY,
                 /*inbound_onion=*/false, /*network_key=*/0};
    connman.Handshake(at_tip, /*successfully_connected=*/true, services,
                      services, PROTOCOL_VERSION, /*relay_txs=*/true,
                      /*starting_height=*/tip->nHeight);
    connman.FlushSendBuffer(at_tip);

    constexpr int k_ahead_peers{6};
    std::vector<std::unique_ptr<CNode>> ahead;
    ahead.reserve(k_ahead_peers);
    for (int i = 0; i < k_ahead_peers; ++i) {
        ahead.push_back(std::make_unique<CNode>(
            /*id=*/6101 + i, /*sock=*/nullptr, CAddress{},
            static_cast<uint64_t>(6101 + i), /*nLocalHostNonceIn=*/0,
            CAddress{}, strprintf("header-tower-ahead-%d", i),
            ConnectionType::OUTBOUND_FULL_RELAY,
            /*inbound_onion=*/false, /*network_key=*/0));
        connman.Handshake(*ahead.back(), /*successfully_connected=*/true,
                          services, services, PROTOCOL_VERSION,
                          /*relay_txs=*/true,
                          /*starting_height=*/tower.back()->nHeight);
        connman.FlushSendBuffer(*ahead.back());
    }

    SetMockTime(std::chrono::seconds{GetTime() + 180});
    at_tip.fPauseSend = false;
    BOOST_CHECK(peerman.SendMessages(&at_tip));
    BOOST_CHECK_EQUAL(
        CountQueuedGetDataForHash(at_tip, tower.front()->GetBlockHash()), 0U);

    size_t getdata{0};
    int inflight_peers{0};
    for (auto& peer : ahead) {
        peer->fPauseSend = false;
        BOOST_CHECK(peerman.SendMessages(peer.get()));
        getdata += CountQueuedGetDataForHash(*peer, tower.front()->GetBlockHash());
        CNodeStateStats st;
        BOOST_REQUIRE(peerman.GetNodeStateStats(peer->GetId(), st));
        BOOST_CHECK_EQUAL(st.nSyncHeight, tower.back()->nHeight);
        if (!st.vHeightInFlight.empty()) ++inflight_peers;
    }
    BOOST_REQUIRE_MESSAGE(getdata > 0,
                          "peers advertising the HEADER_ONLY tower must be "
                          "GETDATA sources without a duplicate HEADERS batch");
    BOOST_REQUIRE_MESSAGE(inflight_peers > 0,
                          "inflight must become nonzero once the selector "
                          "targets the header tower");

    peerman.FinalizeNode(at_tip);
    for (auto& peer : ahead) peerman.FinalizeNode(*peer);
    NeutralizeUnconnectedHeaders(chainman);
    peerman.ResetMatMulVerifyAdmissionForTest();
    node::matmul_trusted::ResetForTest();
}

BOOST_AUTO_TEST_CASE(best_header_follows_headers_only_suffix_not_pinned_to_tip)
{
    // macpro2 0.34.5: getchaintips 200258 headers-only branchlen=944 while
    // getblockchaininfo headers==blocks. Same-chain suffix must be the
    // download target. ConnectTip is unchanged.
    LOCK(NetEventsInterface::g_msgproc_mutex);
    node::matmul_trusted::ResetForTest();
    BOOST_REQUIRE(!node::matmul_trusted::IsConfigured());
    ResetSharedPeermanFixture(m_node);
    ChainstateManager& chainman{*Assert(m_node.chainman)};
    const CBlockIndex* tip{
        WITH_LOCK(::cs_main, return chainman.ActiveChain().Tip())};
    BOOST_REQUIRE(tip != nullptr);

    std::vector<CBlockIndex*> suffix;
    const CBlockIndex* walk{tip};
    for (unsigned int tag = 0xd0; tag < 0xd0 + 20; ++tag) {
        suffix.push_back(MakePeermanHeaderChild(chainman, *walk, tag));
        walk = suffix.back();
    }
    BOOST_REQUIRE_EQUAL(suffix.size(), 20U);
    BOOST_CHECK(WITH_LOCK(::cs_main, {
        return suffix.back()->nChainWork > tip->nChainWork &&
               suffix.back()->GetAncestor(tip->nHeight) == tip;
    }));

    WITH_LOCK(::cs_main, {
        BOOST_CHECK_MESSAGE(
            chainman.m_best_header == suffix.back(),
            "ingesting a 20-header same-chain suffix must leave m_best_header "
            "on that tip, not the connected block");
        chainman.SetBestHeader(const_cast<CBlockIndex*>(tip));
        BOOST_CHECK_EQUAL(chainman.m_best_header, tip);
        chainman.EnsureBestHeaderNotBehindConnectedTip();
        BOOST_CHECK_EQUAL(chainman.m_best_header, suffix.back());
        chainman.SetBestHeader(const_cast<CBlockIndex*>(tip));
        chainman.RecalculateBestHeader();
        BOOST_CHECK_EQUAL(chainman.m_best_header, suffix.back());
        BOOST_CHECK_GT(chainman.m_best_header->nHeight, tip->nHeight);
    });
}

BOOST_AUTO_TEST_CASE(best_header_follows_heavier_disconnected_fork_not_pinned_to_tip)
{
    // jarekpiot 2026-08-28, sealed v0.34.4, GPU authority, never ran
    // invalidateblock: minority 8b5da5a5@199326, ingested 33c834f8 tower
    // to 0d5ffded@199398 (branchlen 104, more nChainWork), getchaintips
    // showed the branchtip, getblockchaininfo headers==blocks because
    // EnsureBestHeaderNotBehindConnectedTip + the IsConfigured overlay
    // pinned m_best_header to the connected tip. Floor, do not pin.
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
    BOOST_REQUIRE(node::matmul_trusted::IsConfigured());
    BOOST_REQUIRE(!node::matmul_trusted::IsTrustedMirror());
    struct VerifierReset {
        ~VerifierReset() { node::matmul_trusted::ResetForTest(); }
    } verifier_reset;

    ResetSharedPeermanFixture(m_node);
    ChainstateManager& chainman{*Assert(m_node.chainman)};
    PeerManager& peerman{*Assert(m_node.peerman)};
    ConnmanTestMsg& connman{static_cast<ConnmanTestMsg&>(*m_node.connman)};

    const CBlockIndex* fork_root{
        WITH_LOCK(::cs_main, return chainman.ActiveChain().Tip())};
    BOOST_REQUIRE(fork_root != nullptr);
    for (int i = 0; i < 8; ++i) {
        mineBlock(m_node, std::chrono::seconds{fork_root->GetBlockTime() + 1 + i});
    }
    const CBlockIndex* tip{
        WITH_LOCK(::cs_main, return chainman.ActiveChain().Tip())};
    BOOST_REQUIRE(tip != nullptr);
    BOOST_REQUIRE_EQUAL(tip->nHeight, fork_root->nHeight + 8);
    {
        LOCK(::cs_main);
        for (CBlockIndex* walk{const_cast<CBlockIndex*>(tip)}; walk != nullptr;
             walk = walk->pprev) {
            walk->nAuthenticatedChainWork = walk->nChainWork;
        }
        chainman.SetBestHeader(const_cast<CBlockIndex*>(tip));
        peerman.SetBestBlock(tip->nHeight,
                             std::chrono::seconds{tip->GetBlockTime()});
    }

    std::vector<CBlockIndex*> fork;
    const CBlockIndex* walk{fork_root};
    for (unsigned int tag = 0xb0; tag < 0xb0 + 16; ++tag) {
        fork.push_back(MakePeermanHeaderChild(chainman, *walk, tag));
        walk = fork.back();
    }
    BOOST_REQUIRE_EQUAL(fork.size(), 16U);
    BOOST_CHECK(WITH_LOCK(::cs_main, return fork.back()->nChainWork > tip->nChainWork));
    BOOST_CHECK(WITH_LOCK(::cs_main, return fork.back()->GetAncestor(tip->nHeight) != tip));

    WITH_LOCK(::cs_main, {
        BOOST_CHECK_MESSAGE(
            chainman.m_best_header == fork.back(),
            "configured GPU authority must keep m_best_header on the heavier "
            "disconnected tower after ingest, not undo it back to the tip");
        chainman.SetBestHeader(const_cast<CBlockIndex*>(tip));
        BOOST_CHECK_EQUAL(chainman.m_best_header, tip);
        chainman.EnsureBestHeaderNotBehindConnectedTip();
        BOOST_CHECK_EQUAL(chainman.m_best_header, fork.back());
        BOOST_CHECK_GT(chainman.m_best_header->nHeight, tip->nHeight);
    });

    SetMockTime(std::chrono::seconds{tip->GetBlockTime() + 55 * 3600});
    BOOST_REQUIRE(!chainman.IsInitialBlockDownload());

    const ServiceFlags services{ServiceFlags(
        NODE_NETWORK | NODE_WITNESS | NODE_MATMUL_CONSENSUS)};
    CNode peer{/*id=*/5500, /*sock=*/nullptr, CAddress{},
               /*nKeyedNetGroupIn=*/5500, /*nLocalHostNonceIn=*/0,
               CAddress{}, /*addrNameIn=*/"jarekpiot-heavier-tower",
               ConnectionType::OUTBOUND_FULL_RELAY,
               /*inbound_onion=*/false, /*network_key=*/0};
    connman.Handshake(peer, /*successfully_connected=*/true, services, services,
                      PROTOCOL_VERSION, /*relay_txs=*/true,
                      /*starting_height=*/fork.back()->nHeight);
    connman.FlushSendBuffer(peer);

    std::vector<CBlock> hdrs;
    hdrs.reserve(fork.size());
    for (CBlockIndex* idx : fork) hdrs.emplace_back(idx->GetBlockHeader());
    BOOST_REQUIRE(connman.ReceiveMsgFrom(
        peer, NetMsg::Make(NetMsgType::HEADERS, TX_WITH_WITNESS(hdrs))));
    peer.fPauseSend = false;
    (void)connman.ProcessMessagesOnce(peer);
    connman.FlushSendBuffer(peer);

    SetMockTime(std::chrono::seconds{GetTime() + 180});
    BOOST_CHECK(peerman.SendMessages(&peer));
    BOOST_CHECK_EQUAL(
        WITH_LOCK(::cs_main, return chainman.m_best_header), fork.back());
    BOOST_REQUIRE_MESSAGE(
        CountQueuedGetDataForHash(peer, fork.front()->GetBlockHash()) > 0,
        "heavier disconnected tower must still be GETDATA'd after Ensure");

    peerman.FinalizeNode(peer);
    NeutralizeUnconnectedHeaders(chainman);
    peerman.ResetMatMulVerifyAdmissionForTest();
}

BOOST_AUTO_TEST_CASE(must_probe_getheaders_without_sync_slot_or_network)
{
    // Live 2026-08-28: HeaderSyncMustProbe was true (VERSION 199546 vs tip
    // 199312, BestKnown not extending) but the send sat inside
    // !fSyncStarted && CanServeBlocks. Slot-held peers and peers without
    // NODE_NETWORK (CanServeBlocks is NETWORK|LIMITED) never got getheaders.
    LOCK(NetEventsInterface::g_msgproc_mutex);
    node::matmul_trusted::ResetForTest();
    ResetSharedPeermanFixture(m_node);
    ChainstateManager& chainman{*Assert(m_node.chainman)};
    PeerManager& peerman{*Assert(m_node.peerman)};
    ConnmanTestMsg& connman{static_cast<ConnmanTestMsg&>(*m_node.connman)};
    const CBlockIndex* tip{
        WITH_LOCK(::cs_main, return chainman.ActiveChain().Tip())};
    BOOST_REQUIRE(tip != nullptr);
    {
        LOCK(::cs_main);
        chainman.SetBestHeader(const_cast<CBlockIndex*>(tip));
        peerman.SetBestBlock(tip->nHeight,
                             std::chrono::seconds{tip->GetBlockTime()});
    }

    auto handshake_peer = [&](CNode& node, ServiceFlags services, int start_h) {
        connman.Handshake(node, /*successfully_connected=*/true, services,
                          services, PROTOCOL_VERSION, /*relay_txs=*/true,
                          /*starting_height=*/start_h);
        connman.FlushSendBuffer(node);
    };

    // 1) No NODE_NETWORK and no NODE_NETWORK_LIMITED: CanServeBlocks is false.
    // Must be inbound. Outbound ExpectServicesFromConn() disconnects at VERSION
    // when HasAllDesirableServiceFlags fails (no NODE_NETWORK), so SendMessages
    // returns before the hoisted probe. Live stall peers are NETWORK; this
    // case only proves the fan-out is not CanServeBlocks-gated.
    {
        const ServiceFlags no_network{ServiceFlags(NODE_WITNESS | NODE_MATMUL_CONSENSUS)};
        CNode witness_only{/*id=*/5300, /*sock=*/nullptr, CAddress{},
                           /*nKeyedNetGroupIn=*/5300, /*nLocalHostNonceIn=*/0,
                           CAddress{}, /*addrNameIn=*/"must-probe-no-network",
                           ConnectionType::INBOUND,
                           /*inbound_onion=*/false, /*network_key=*/0};
        handshake_peer(witness_only, no_network, tip->nHeight + 234);
        BOOST_REQUIRE_MESSAGE(!witness_only.fDisconnect,
                              "inbound witness-only peer must stay connected");
        BOOST_REQUIRE(witness_only.fSuccessfullyConnected);
        SetMockTime(std::chrono::seconds{GetTime() + 180});
        witness_only.fPauseSend = false;
        BOOST_CHECK(peerman.SendMessages(&witness_only));
        BOOST_REQUIRE_MESSAGE(
            HasQueuedMessageType(witness_only, NetMsgType::GETHEADERS),
            "must_probe must send getheaders even when the peer lacks "
            "NODE_NETWORK (CanServeBlocks false)");
        CNodeStateStats stats;
        BOOST_REQUIRE(peerman.GetNodeStateStats(witness_only.GetId(), stats));
        BOOST_CHECK(!stats.m_headers_sync_started);
        peerman.FinalizeNode(witness_only);
    }

    // 2) NETWORK peer already holds the IBD slot (fSyncStarted). Probe
    // must still send and must not be the thing that claimed the slot.
    {
        const ServiceFlags services{ServiceFlags(
            NODE_NETWORK | NODE_WITNESS | NODE_MATMUL_CONSENSUS)};
        CNode slotted{/*id=*/5301, /*sock=*/nullptr, CAddress{},
                      /*nKeyedNetGroupIn=*/5301, /*nLocalHostNonceIn=*/0,
                      CAddress{}, /*addrNameIn=*/"must-probe-slot-held",
                      ConnectionType::OUTBOUND_FULL_RELAY,
                      /*inbound_onion=*/false, /*network_key=*/0};
        // Near-tip so the first SendMessages claims the scarce IBD slot.
        SetMockTime(std::chrono::seconds{tip->GetBlockTime() + 60});
        handshake_peer(slotted, services, tip->nHeight + 234);
        BOOST_CHECK(peerman.SendMessages(&slotted));
        CNodeStateStats after_slot;
        BOOST_REQUIRE(peerman.GetNodeStateStats(slotted.GetId(), after_slot));
        BOOST_REQUIRE_MESSAGE(after_slot.m_headers_sync_started,
                              "test setup: first send must claim fSyncStarted");
        connman.FlushSendBuffer(slotted);
        slotted.fPauseSend = false;
        SetMockTime(std::chrono::seconds{GetTime() + 180});
        BOOST_CHECK(peerman.SendMessages(&slotted));
        BOOST_REQUIRE_MESSAGE(
            HasQueuedMessageType(slotted, NetMsgType::GETHEADERS),
            "must_probe must send getheaders after fSyncStarted is set");
        CNodeStateStats after_probe;
        BOOST_REQUIRE(peerman.GetNodeStateStats(slotted.GetId(), after_probe));
        BOOST_CHECK(after_probe.m_headers_sync_started);
        peerman.FinalizeNode(slotted);
    }

    peerman.ResetMatMulVerifyAdmissionForTest();
    node::matmul_trusted::ResetForTest();
}

BOOST_AUTO_TEST_CASE(invalidateblock_moves_best_header_off_dead_branch_and_getheaders_resumes)
{
    // Live Case B: snapshot tip 199300, m_best_header left on the operator's
    // own 199303 suffix after invalidateblock. follows_tip was true (the
    // dead headers still descend from the snapshot), so
    // EnsureBestHeaderNotBehindConnectedTip left it. best_header_ahead=3,
    // in_flight=0, Timeout downloading headers, never chased 199546.
    LOCK(NetEventsInterface::g_msgproc_mutex);
    node::matmul_trusted::ResetForTest();
    ResetSharedPeermanFixture(m_node);
    ChainstateManager& chainman{*Assert(m_node.chainman)};
    PeerManager& peerman{*Assert(m_node.peerman)};
    ConnmanTestMsg& connman{static_cast<ConnmanTestMsg&>(*m_node.connman)};
    const CBlockIndex* tip{
        WITH_LOCK(::cs_main, return chainman.ActiveChain().Tip())};
    BOOST_REQUIRE(tip != nullptr);

    std::vector<CBlockIndex*> suffix;
    const CBlockIndex* walk{tip};
    for (unsigned int tag = 0xf0; tag < 0xf0 + 3; ++tag) {
        suffix.push_back(MakePeermanHeaderChild(chainman, *walk, tag));
        walk = suffix.back();
    }
    BOOST_REQUIRE_EQUAL(suffix.size(), 3U);
    CBlockIndex* dead_tip{suffix.back()};
    CBlockIndex* dead_root{suffix.front()};

    {
        LOCK(::cs_main);
        chainman.SetBestHeader(dead_tip);
        BOOST_CHECK_EQUAL(chainman.m_best_header, dead_tip);
        BOOST_CHECK(dead_tip->GetAncestor(tip->nHeight) == tip);
    }

    BlockValidationState invalidate_state;
    BOOST_REQUIRE(chainman.ActiveChainstate().InvalidateBlock(
        invalidate_state, dead_root));

    {
        LOCK(::cs_main);
        // RecalculateBestHeader may already have moved it. Re-pin onto the
        // failed suffix to reproduce the live stall, then the SendMessages
        // self-heal must move it.
        chainman.SetBestHeader(dead_tip);
        BOOST_REQUIRE(dead_tip->nStatus & BLOCK_FAILED_MASK);
        chainman.EnsureBestHeaderNotBehindConnectedTip();
        BOOST_REQUIRE(chainman.m_best_header != nullptr);
        BOOST_CHECK_NE(chainman.m_best_header, dead_tip);
        BOOST_CHECK_EQUAL(chainman.m_best_header->nStatus & BLOCK_FAILED_MASK, 0);
        BOOST_CHECK(chainman.m_best_header->IsValid(BLOCK_VALID_TREE));
        BOOST_CHECK(chainman.m_best_header == tip ||
                    chainman.m_best_header->GetAncestor(tip->nHeight) == tip);
        chainman.SetBestHeader(dead_tip);
        peerman.SetBestBlock(tip->nHeight,
                             std::chrono::seconds{tip->GetBlockTime()});
    }

    const ServiceFlags services{ServiceFlags(
        NODE_NETWORK | NODE_WITNESS | NODE_MATMUL_CONSENSUS)};
    CNode peer{/*id=*/5400, /*sock=*/nullptr, CAddress{},
               /*nKeyedNetGroupIn=*/5400, /*nLocalHostNonceIn=*/0,
               CAddress{}, /*addrNameIn=*/"dead-best-header",
               ConnectionType::OUTBOUND_FULL_RELAY,
               /*inbound_onion=*/false, /*network_key=*/0};
    connman.Handshake(peer, /*successfully_connected=*/true, services, services,
                      PROTOCOL_VERSION, /*relay_txs=*/true,
                      /*starting_height=*/tip->nHeight + 246);
    connman.FlushSendBuffer(peer);
    SetMockTime(std::chrono::seconds{GetTime() + 180});
    BOOST_CHECK(peerman.SendMessages(&peer));
    BOOST_REQUIRE_MESSAGE(
        HasQueuedMessageType(peer, NetMsgType::GETHEADERS),
        "after invalidateblock of m_best_header's branch, getheaders must resume");
    BOOST_CHECK(WITH_LOCK(::cs_main, {
        return chainman.m_best_header != nullptr &&
               (chainman.m_best_header->nStatus & BLOCK_FAILED_MASK) == 0 &&
               chainman.m_best_header != dead_tip;
    }));

    peerman.FinalizeNode(peer);
    peerman.ResetMatMulVerifyAdmissionForTest();
    node::matmul_trusted::ResetForTest();
}

BOOST_AUTO_TEST_CASE(initial_headers_sync_prefers_checkpoint_height_peer)
{
    // MendeMatthias / sealed v0.34.4: a fresh node with the network at
    // 200131 gave the scarce IBD slot to peers at 128530 / 185109 / 189611
    // (7898–9850 bytes of getheaders, 23–29 MB back) while the tip
    // advertiser received 90 bytes and one request. Presync ended below
    // checkpoint 186000, failed low-work, disconnected, restarted.
    // Regtest last checkpoint is 0; inject the mainnet anchor.
    LOCK(NetEventsInterface::g_msgproc_mutex);
    node::matmul_trusted::ResetForTest();
    ResetSharedPeermanFixture(m_node);
    PeerManager& peerman{*Assert(m_node.peerman)};
    ConnmanTestMsg& connman{static_cast<ConnmanTestMsg&>(*m_node.connman)};
    const CBlockIndex* tip{
        WITH_LOCK(::cs_main, return m_node.chainman->ActiveChain().Tip())};
    BOOST_REQUIRE(tip != nullptr);
    SetMockTime(std::chrono::seconds{tip->GetBlockTime()} + std::chrono::hours{48});
    peerman.SetInitialHeadersSyncAnchorForTest(186000);

    const ServiceFlags services{ServiceFlags(
        NODE_NETWORK | NODE_WITNESS | NODE_MATMUL_CONSENSUS)};
    const CAddress addr_short{
        LookupNumeric("192.0.2.11", Params().GetDefaultPort()), NODE_NONE};
    const CAddress addr_tall{
        LookupNumeric("192.0.2.12", Params().GetDefaultPort()), NODE_NONE};
    CNode short_peer{/*id=*/5400, /*sock=*/nullptr, addr_short,
                     /*nKeyedNetGroupIn=*/5400, /*nLocalHostNonceIn=*/0,
                     CAddress{}, /*addrNameIn=*/"initial-sync-short",
                     ConnectionType::OUTBOUND_FULL_RELAY,
                     /*inbound_onion=*/false, /*network_key=*/0};
    CNode tall_peer{/*id=*/5401, /*sock=*/nullptr, addr_tall,
                    /*nKeyedNetGroupIn=*/5401, /*nLocalHostNonceIn=*/0,
                    CAddress{}, /*addrNameIn=*/"initial-sync-tall",
                    ConnectionType::OUTBOUND_FULL_RELAY,
                    /*inbound_onion=*/false, /*network_key=*/0};
    struct FinalizePeers {
        PeerManager& peerman;
        CNode& a;
        CNode& b;
        ~FinalizePeers()
        {
            peerman.FinalizeNode(a);
            peerman.FinalizeNode(b);
        }
    } finalize{peerman, short_peer, tall_peer};

    connman.Handshake(short_peer, /*successfully_connected=*/true, services,
                      services, PROTOCOL_VERSION, /*relay_txs=*/true,
                      /*starting_height=*/128530);
    CNodeStateStats short_stats;
    BOOST_REQUIRE(peerman.GetNodeStateStats(short_peer.GetId(), short_stats));
    BOOST_REQUIRE(short_stats.m_headers_sync_started);
    BOOST_REQUIRE_EQUAL(short_stats.m_total_headers_sync_peer_count, 1);

    connman.Handshake(tall_peer, /*successfully_connected=*/true, services,
                      services, PROTOCOL_VERSION, /*relay_txs=*/true,
                      /*starting_height=*/200131);
    BOOST_REQUIRE(peerman.GetNodeStateStats(short_peer.GetId(), short_stats));
    CNodeStateStats tall_stats;
    BOOST_REQUIRE(peerman.GetNodeStateStats(tall_peer.GetId(), tall_stats));
    BOOST_CHECK_MESSAGE(
        !short_stats.m_headers_sync_started,
        "checkpoint-height peer must take the IBD slot from a short presync");
    BOOST_CHECK(tall_stats.m_headers_sync_started);
    BOOST_CHECK_EQUAL(tall_stats.m_total_headers_sync_peer_count, 1);
}

BOOST_AUTO_TEST_CASE(initial_headers_sync_deprioritizes_low_work_failure)
{
    LOCK(NetEventsInterface::g_msgproc_mutex);
    node::matmul_trusted::ResetForTest();
    ResetSharedPeermanFixture(m_node);
    PeerManager& peerman{*Assert(m_node.peerman)};
    ConnmanTestMsg& connman{static_cast<ConnmanTestMsg&>(*m_node.connman)};
    const CBlockIndex* tip{
        WITH_LOCK(::cs_main, return m_node.chainman->ActiveChain().Tip())};
    BOOST_REQUIRE(tip != nullptr);
    SetMockTime(std::chrono::seconds{tip->GetBlockTime()} + std::chrono::hours{48});

    const ServiceFlags services{ServiceFlags(
        NODE_NETWORK | NODE_WITNESS | NODE_MATMUL_CONSENSUS)};
    const CAddress addr_failed{
        LookupNumeric("192.0.2.21", Params().GetDefaultPort()), NODE_NONE};
    const CAddress addr_ok{
        LookupNumeric("192.0.2.22", Params().GetDefaultPort()), NODE_NONE};
    CNode failed_peer{/*id=*/5410, /*sock=*/nullptr, addr_failed,
                      /*nKeyedNetGroupIn=*/5410, /*nLocalHostNonceIn=*/0,
                      CAddress{}, /*addrNameIn=*/"initial-sync-low-work",
                      ConnectionType::OUTBOUND_FULL_RELAY,
                      /*inbound_onion=*/false, /*network_key=*/0};
    CNode ok_peer{/*id=*/5411, /*sock=*/nullptr, addr_ok,
                  /*nKeyedNetGroupIn=*/5411, /*nLocalHostNonceIn=*/0,
                  CAddress{}, /*addrNameIn=*/"initial-sync-ok",
                  ConnectionType::OUTBOUND_FULL_RELAY,
                  /*inbound_onion=*/false, /*network_key=*/0};
    struct FinalizePeers {
        PeerManager& peerman;
        CNode& a;
        CNode& b;
        ~FinalizePeers()
        {
            peerman.FinalizeNode(a);
            peerman.FinalizeNode(b);
        }
    } finalize{peerman, failed_peer, ok_peer};

    connman.Handshake(failed_peer, /*successfully_connected=*/true, services,
                      services, PROTOCOL_VERSION, /*relay_txs=*/true,
                      /*starting_height=*/200131);
    CNodeStateStats failed_stats;
    BOOST_REQUIRE(peerman.GetNodeStateStats(failed_peer.GetId(), failed_stats));
    BOOST_REQUIRE(failed_stats.m_headers_sync_started);
    peerman.NoteLowWorkHeadersSyncFailureForTest(failed_peer.addr);

    connman.Handshake(ok_peer, /*successfully_connected=*/true, services,
                      services, PROTOCOL_VERSION, /*relay_txs=*/true,
                      /*starting_height=*/200131);
    BOOST_REQUIRE(peerman.GetNodeStateStats(failed_peer.GetId(), failed_stats));
    CNodeStateStats ok_stats;
    BOOST_REQUIRE(peerman.GetNodeStateStats(ok_peer.GetId(), ok_stats));
    BOOST_CHECK_MESSAGE(
        !failed_stats.m_headers_sync_started,
        "a peer that already failed low-work presync must yield the IBD slot");
    BOOST_CHECK(ok_stats.m_headers_sync_started);
    BOOST_CHECK_EQUAL(ok_stats.m_total_headers_sync_peer_count, 1);
}

BOOST_AUTO_TEST_CASE(low_work_presync_failure_does_not_immediately_retry)
{
    // Auditor: 161 PRESYNC STARTS / 162 ABORTS / 1 COMPLETE on a fresh
    // empty datadir. Failed addresses were re-probed every 2 minutes
    // because m_low_work_headers_failed was only a slot-preference hint.
    LOCK(NetEventsInterface::g_msgproc_mutex);
    node::matmul_trusted::ResetForTest();
    ResetSharedPeermanFixture(m_node);
    PeerManager& peerman{*Assert(m_node.peerman)};
    ConnmanTestMsg& connman{static_cast<ConnmanTestMsg&>(*m_node.connman)};
    const CBlockIndex* tip{
        WITH_LOCK(::cs_main, return m_node.chainman->ActiveChain().Tip())};
    BOOST_REQUIRE(tip != nullptr);
    SetMockTime(std::chrono::seconds{tip->GetBlockTime()} + std::chrono::hours{48});
    peerman.SetInitialHeadersSyncAnchorForTest(186000);

    const ServiceFlags services{ServiceFlags(
        NODE_NETWORK | NODE_WITNESS | NODE_MATMUL_CONSENSUS)};
    const CAddress addr{
        LookupNumeric("192.0.2.31", Params().GetDefaultPort()), NODE_NONE};
    CNode first{/*id=*/5430, /*sock=*/nullptr, addr,
                /*nKeyedNetGroupIn=*/5430, /*nLocalHostNonceIn=*/0,
                CAddress{}, /*addrNameIn=*/"low-work-first",
                ConnectionType::OUTBOUND_FULL_RELAY,
                /*inbound_onion=*/false, /*network_key=*/0};
    connman.Handshake(first, /*successfully_connected=*/true, services,
                      services, PROTOCOL_VERSION, /*relay_txs=*/true,
                      /*starting_height=*/200131);
    CNodeStateStats first_stats;
    BOOST_REQUIRE(peerman.GetNodeStateStats(first.GetId(), first_stats));
    BOOST_REQUIRE(first_stats.m_headers_sync_started);
    peerman.NoteLowWorkHeadersSyncFailureForTest(first.addr);
    peerman.FinalizeNode(first);

    CNode retry{/*id=*/5431, /*sock=*/nullptr, addr,
                /*nKeyedNetGroupIn=*/5431, /*nLocalHostNonceIn=*/0,
                CAddress{}, /*addrNameIn=*/"low-work-retry",
                ConnectionType::OUTBOUND_FULL_RELAY,
                /*inbound_onion=*/false, /*network_key=*/0};
    connman.Handshake(retry, /*successfully_connected=*/true, services,
                      services, PROTOCOL_VERSION, /*relay_txs=*/true,
                      /*starting_height=*/200131);
    CNodeStateStats retry_stats;
    BOOST_REQUIRE(peerman.GetNodeStateStats(retry.GetId(), retry_stats));
    BOOST_CHECK_MESSAGE(
        !retry_stats.m_headers_sync_started,
        "a just-failed presync address must not immediately reclaim the IBD slot");
    BOOST_CHECK(!HasQueuedMessageType(retry, NetMsgType::GETHEADERS));

    SetMockTime(std::chrono::seconds{GetTime() + 121});
    peerman.FinalizeNode(retry);
    CNode later{/*id=*/5432, /*sock=*/nullptr, addr,
                /*nKeyedNetGroupIn=*/5432, /*nLocalHostNonceIn=*/0,
                CAddress{}, /*addrNameIn=*/"low-work-later",
                ConnectionType::OUTBOUND_FULL_RELAY,
                /*inbound_onion=*/false, /*network_key=*/0};
    connman.Handshake(later, /*successfully_connected=*/true, services,
                      services, PROTOCOL_VERSION, /*relay_txs=*/true,
                      /*starting_height=*/200131);
    CNodeStateStats later_stats;
    BOOST_REQUIRE(peerman.GetNodeStateStats(later.GetId(), later_stats));
    BOOST_CHECK_MESSAGE(
        later_stats.m_headers_sync_started,
        "after backoff the same address may retry when no preferred peer is live");
    peerman.FinalizeNode(later);
}

BOOST_AUTO_TEST_CASE(recalculate_best_header_runs_when_unconfigured)
{
    // Independent validators: -matmulvalidation=consensus and no
    // -matmultrustedpubkey. IsConfigured() is false; startup and
    // ActivateSnapshot must still call RecalculateBestHeader, the only
    // path that can lower m_best_header (MendeMatthias).
    LOCK(NetEventsInterface::g_msgproc_mutex);
    node::matmul_trusted::ResetForTest();
    BOOST_REQUIRE(!node::matmul_trusted::IsConfigured());
    ResetSharedPeermanFixture(m_node);
    ChainstateManager& chainman{*Assert(m_node.chainman)};
    const CBlockIndex* tip{
        WITH_LOCK(::cs_main, return chainman.ActiveChain().Tip())};
    BOOST_REQUIRE(tip != nullptr);
    if (tip->pprev == nullptr) {
        mineBlock(m_node, std::chrono::seconds{tip->GetBlockTime() + 1});
        tip = WITH_LOCK(::cs_main, return chainman.ActiveChain().Tip());
        BOOST_REQUIRE(tip != nullptr);
    }
    BOOST_REQUIRE(tip->pprev != nullptr);
    WITH_LOCK(::cs_main, {
        chainman.SetBestHeader(const_cast<CBlockIndex*>(tip->pprev));
        BOOST_CHECK_LT(chainman.m_best_header->nHeight, tip->nHeight);
        chainman.RecalculateBestHeader();
        BOOST_REQUIRE(chainman.m_best_header != nullptr);
        BOOST_CHECK_GE(chainman.m_best_header->nHeight, tip->nHeight);
    });
}

BOOST_AUTO_TEST_CASE(silent_getdata_peer_rerequested_from_other_and_tip_advances)
{
    // Live 0.34.5 macpro2: headers 960 ahead, one peer accepted getdata for
    // tip+1 and never delivered. select=root_in_flight looped forever.
    // SendMessages ran on other peers (probe spam) and never evaluated the
    // silent owner's timeout. getblockfrompeer to a different peer advanced
    // one block; the next hole re-wedged. ExpireOverdueBlockDownloads must
    // free the silent owner when ANY peer is serviced, pause that owner, and
    // let another peer's GETDATA connect the body (full validation).
    LOCK(NetEventsInterface::g_msgproc_mutex);
    ResetSharedPeermanFixture(m_node);
    ChainstateManager& chainman{*Assert(m_node.chainman)};
    PeerManager& peerman{*Assert(m_node.peerman)};
    ConnmanTestMsg& connman{static_cast<ConnmanTestMsg&>(*m_node.connman)};
    const CBlockIndex* starting_tip{
        WITH_LOCK(::cs_main, return chainman.ActiveChain().Tip())};
    BOOST_REQUIRE(starting_tip != nullptr);
    SetMockTime(std::chrono::seconds{starting_tip->GetBlockTime() + 3600});
    BOOST_REQUIRE(!chainman.IsInitialBlockDownload());

    CBlock child = node::BlockAssembler{
        chainman.ActiveChainstate(), nullptr, {}, m_node}
                       .CreateNewBlock()
                       ->block;
    child.hashMerkleRoot = BlockMerkleRoot(child);
    BOOST_REQUIRE(MineHeaderForConsensus(
        child, static_cast<uint32_t>(starting_tip->nHeight + 1),
        chainman.GetConsensus(), 5'000'000,
        starting_tip->GetMedianTimePast()));
    child.fChecked = true;
    BlockValidationState hdr_state;
    BOOST_REQUIRE_MESSAGE(
        chainman.ProcessNewBlockHeaders(
            {{child.GetBlockHeader()}}, /*min_pow_checked=*/true, hdr_state),
        hdr_state.ToString());
    const uint256 child_hash{child.GetHash()};
    CBlockIndex* child_index{WITH_LOCK(
        ::cs_main, return chainman.m_blockman.LookupBlockIndex(child_hash))};
    BOOST_REQUIRE(child_index != nullptr);

    std::vector<CBlockIndex*> headers{child_index};
    const CBlockIndex* walk{child_index};
    for (unsigned int tag = 0x51; tag < 0x51 + 5; ++tag) {
        walk = MakePeermanHeaderChild(chainman, *walk, tag);
        headers.push_back(const_cast<CBlockIndex*>(walk));
    }
    BOOST_REQUIRE_EQUAL(headers.size(), 6U);
    BOOST_CHECK_EQUAL(
        WITH_LOCK(::cs_main, return chainman.ActiveChain().Tip()->nHeight),
        starting_tip->nHeight);
    BOOST_CHECK_EQUAL(
        WITH_LOCK(::cs_main, return chainman.m_best_header->nHeight),
        starting_tip->nHeight + 6);

    const ServiceFlags services{ServiceFlags(NODE_NETWORK | NODE_WITNESS)};
    CNode silent{/*id=*/5420, /*sock=*/nullptr, CAddress{},
                 /*nKeyedNetGroupIn=*/5420, /*nLocalHostNonceIn=*/0,
                 CAddress{}, /*addrNameIn=*/"h3a-silent",
                 ConnectionType::OUTBOUND_FULL_RELAY,
                 /*inbound_onion=*/false, /*network_key=*/0};
    CNode other{/*id=*/5421, /*sock=*/nullptr, CAddress{},
                /*nKeyedNetGroupIn=*/5421, /*nLocalHostNonceIn=*/0,
                CAddress{}, /*addrNameIn=*/"h3a-other",
                ConnectionType::OUTBOUND_FULL_RELAY,
                /*inbound_onion=*/false, /*network_key=*/0};
    CNode spammer{/*id=*/5422, /*sock=*/nullptr, CAddress{},
                  /*nKeyedNetGroupIn=*/5422, /*nLocalHostNonceIn=*/0,
                  CAddress{}, /*addrNameIn=*/"h3a-probe-spam",
                  ConnectionType::INBOUND,
                  /*inbound_onion=*/false, /*network_key=*/0};
    connman.Handshake(silent, /*successfully_connected=*/true, services,
                      services, PROTOCOL_VERSION, /*relay_txs=*/true);
    connman.Handshake(other, /*successfully_connected=*/true, services,
                      services, PROTOCOL_VERSION, /*relay_txs=*/true);
    connman.Handshake(spammer, /*successfully_connected=*/true, services,
                      services, PROTOCOL_VERSION, /*relay_txs=*/true,
                      /*starting_height=*/0);
    connman.AddTestNode(silent);
    connman.AddTestNode(other);
    connman.AddTestNode(spammer);
    connman.FlushSendBuffer(silent);
    connman.FlushSendBuffer(other);
    connman.FlushSendBuffer(spammer);
    silent.fPauseSend = false;
    other.fPauseSend = false;
    spammer.fPauseSend = false;
    struct FinalizePeers {
        PeerManager& peerman;
        ConnmanTestMsg& connman;
        CNode& silent;
        CNode& other;
        CNode& spammer;
        ~FinalizePeers()
        {
            peerman.FinalizeNode(silent);
            peerman.FinalizeNode(other);
            peerman.FinalizeNode(spammer);
            connman.RemoveTestNode(silent);
            connman.RemoveTestNode(other);
            connman.RemoveTestNode(spammer);
        }
    } finalize{peerman, connman, silent, other, spammer};

    auto advertise = [&](CNode& peer) {
        std::vector<CBlock> hdrs;
        hdrs.reserve(headers.size());
        {
            LOCK(::cs_main);
            for (CBlockIndex* idx : headers) {
                hdrs.emplace_back(idx->GetBlockHeader());
            }
        }
        peer.fPauseSend = false;
        connman.FlushSendBuffer(peer);
        BOOST_REQUIRE(connman.ReceiveMsgFrom(
            peer, NetMsg::Make(NetMsgType::HEADERS, TX_WITH_WITNESS(hdrs))));
        peer.fPauseSend = false;
        (void)connman.ProcessMessagesOnce(peer);
    };
    advertise(silent);
    advertise(other);

    BOOST_CHECK(peerman.SendMessages(&silent));
    CNodeStateStats silent_stats;
    BOOST_REQUIRE(peerman.GetNodeStateStats(silent.GetId(), silent_stats));
    BOOST_REQUIRE_EQUAL(silent_stats.vHeightInFlight.size(), 1U);
    BOOST_CHECK_EQUAL(silent_stats.vHeightInFlight.front(),
                      starting_tip->nHeight + 1);
    BOOST_CHECK(HasQueuedMessageType(silent, NetMsgType::GETDATA));
    connman.FlushSendBuffer(silent);

    // Live shape: msghand services a different peer (probe spam) while the
    // silent owner still holds the only in-flight slot. Do not SendMessages
    // the silent peer — that would hit the old owner-only timeout and hide
    // the global ExpireOverdueBlockDownloads path. Deadline is the spacing
    // formula (90s with one download peer), not a flat 15s.
    SetMockTime(std::chrono::seconds{GetTime() + 136});
    spammer.fPauseSend = false;
    BOOST_CHECK(peerman.SendMessages(&spammer));
    CNodeStateStats silent_after;
    BOOST_REQUIRE(peerman.GetNodeStateStats(silent.GetId(), silent_after));
    BOOST_REQUIRE_MESSAGE(
        silent_after.vHeightInFlight.empty(),
        "SendMessages on an unrelated peer must expire the silent getdata");
    BOOST_CHECK(!silent.fDisconnect);

    silent.fPauseSend = false;
    BOOST_CHECK(peerman.SendMessages(&silent));
    CNodeStateStats silent_paused;
    BOOST_REQUIRE(peerman.GetNodeStateStats(silent.GetId(), silent_paused));
    BOOST_CHECK(silent_paused.vHeightInFlight.empty());
    BOOST_CHECK(!HasQueuedMessageType(silent, NetMsgType::GETDATA));

    connman.FlushSendBuffer(other);
    other.fPauseSend = false;
    BOOST_CHECK(peerman.SendMessages(&other));
    CNodeStateStats other_stats;
    BOOST_REQUIRE(peerman.GetNodeStateStats(other.GetId(), other_stats));
    BOOST_REQUIRE_MESSAGE(
        !other_stats.vHeightInFlight.empty() ||
            HasQueuedMessageType(other, NetMsgType::GETDATA) ||
            CountQueuedGetDataForHash(other, child_hash) > 0,
        "after the silent peer's deadline the hole must be GETDATA'd from a "
        "different peer");
    connman.FlushSendBuffer(other);
    other.fPauseSend = false;

    BOOST_REQUIRE(connman.ReceiveMsgFrom(
        other, NetMsg::Make(NetMsgType::BLOCK, TX_WITH_WITNESS(child))));
    other.fPauseSend = false;
    (void)connman.ProcessMessagesOnce(other);
    m_node.validation_signals->SyncWithValidationInterfaceQueue();

    BOOST_REQUIRE(PeermanWaitFor([&] {
        LOCK(::cs_main);
        const CBlockIndex* idx{
            chainman.m_blockman.LookupBlockIndex(child_hash)};
        return idx != nullptr && (idx->nStatus & BLOCK_HAVE_DATA) != 0;
    }));
    for (int i = 0; i < 5; ++i) {
        (void)peerman.SendMessages(&other);
        m_node.validation_signals->SyncWithValidationInterfaceQueue();
        if (WITH_LOCK(::cs_main, {
                const CBlockIndex* idx{
                    chainman.m_blockman.LookupBlockIndex(child_hash)};
                return idx != nullptr && chainman.ActiveChain().Contains(idx);
            })) {
            break;
        }
    }
    BOOST_REQUIRE_EQUAL(
        WITH_LOCK(::cs_main, return chainman.ActiveChain().Tip()->GetBlockHash()),
        child_hash);

    // Next HEADER_ONLY hole must be requested from the other peer without
    // another manual RPC. The silent owner stays paused.
    connman.FlushSendBuffer(other);
    other.fPauseSend = false;
    BOOST_CHECK(peerman.SendMessages(&other));
    CNodeStateStats next_hole;
    BOOST_REQUIRE(peerman.GetNodeStateStats(other.GetId(), next_hole));
    BOOST_REQUIRE_MESSAGE(
        !next_hole.vHeightInFlight.empty() &&
            next_hole.vHeightInFlight.front() == starting_tip->nHeight + 2,
        "after ConnectTip the next suffix hole must be fetched without RPC");

    NeutralizeUnconnectedHeaders(chainman);
    peerman.ResetMatMulVerifyAdmissionForTest();
}

BOOST_AUTO_TEST_CASE(best_known_probe_is_rate_limited_and_skips_height_zero)
{
    LOCK(NetEventsInterface::g_msgproc_mutex);
    ResetSharedPeermanFixture(m_node);
    ChainstateManager& chainman{*Assert(m_node.chainman)};
    PeerManager& peerman{*Assert(m_node.peerman)};
    ConnmanTestMsg& connman{static_cast<ConnmanTestMsg&>(*m_node.connman)};
    const CBlockIndex* tip{
        WITH_LOCK(::cs_main, return chainman.ActiveChain().Tip())};
    BOOST_REQUIRE(tip != nullptr);
    // Isolated runs sit at genesis (tip=0). Height 0 is then a real IBD
    // peer, not the live 0.34.5 spam (tip=199334, advertisers at 0).
    if (tip->nHeight == 0) {
        mineBlock(m_node, std::chrono::seconds{tip->GetBlockTime() + 1});
        tip = WITH_LOCK(::cs_main, return chainman.ActiveChain().Tip());
        BOOST_REQUIRE(tip != nullptr);
        BOOST_REQUIRE_GT(tip->nHeight, 0);
    }
    {
        LOCK(::cs_main);
        chainman.SetBestHeader(const_cast<CBlockIndex*>(tip));
        peerman.SetBestBlock(tip->nHeight,
                             std::chrono::seconds{tip->GetBlockTime()});
    }

    const ServiceFlags services{ServiceFlags(
        NODE_NETWORK | NODE_WITNESS | NODE_MATMUL_CONSENSUS)};
    CNode probe{/*id=*/5410, /*sock=*/nullptr, CAddress{},
                /*nKeyedNetGroupIn=*/5410, /*nLocalHostNonceIn=*/0,
                CAddress{}, /*addrNameIn=*/"h3b-probe",
                ConnectionType::OUTBOUND_FULL_RELAY,
                /*inbound_onion=*/false, /*network_key=*/0};
    connman.Handshake(probe, /*successfully_connected=*/true, services,
                      services, PROTOCOL_VERSION, /*relay_txs=*/true,
                      /*starting_height=*/tip->nHeight + 100);
    connman.FlushSendBuffer(probe);
    SetMockTime(std::chrono::seconds{GetTime() + 180});
    probe.fPauseSend = false;
    BOOST_CHECK(peerman.SendMessages(&probe));
    BOOST_REQUIRE_MESSAGE(HasQueuedMessageType(probe, NetMsgType::GETHEADERS),
                          "first probe after HEADERS_RESPONSE_TIME must send");
    const size_t first{CountQueuedMessageType(probe, NetMsgType::GETHEADERS)};
    BOOST_CHECK_GE(first, 1U);
    connman.FlushSendBuffer(probe);
    probe.fPauseSend = false;
    BOOST_CHECK(peerman.SendMessages(&probe));
    BOOST_CHECK_EQUAL(CountQueuedMessageType(probe, NetMsgType::GETHEADERS), 0U);
    peerman.FinalizeNode(probe);

    CNode height_zero{/*id=*/5411, /*sock=*/nullptr, CAddress{},
                      /*nKeyedNetGroupIn=*/5411, /*nLocalHostNonceIn=*/0,
                      CAddress{}, /*addrNameIn=*/"h3b-height0",
                      ConnectionType::INBOUND,
                      /*inbound_onion=*/false, /*network_key=*/0};
    SetMockTime(std::chrono::seconds{tip->GetBlockTime() + 55 * 3600});
    connman.Handshake(height_zero, /*successfully_connected=*/true, services,
                      services, PROTOCOL_VERSION, /*relay_txs=*/true,
                      /*starting_height=*/0);
    connman.FlushSendBuffer(height_zero);
    SetMockTime(std::chrono::seconds{GetTime() + 180});
    height_zero.fPauseSend = false;
    BOOST_CHECK(peerman.SendMessages(&height_zero));
    BOOST_CHECK_MESSAGE(
        !HasQueuedMessageType(height_zero, NetMsgType::GETHEADERS),
        "peers advertising height 0 must not be best-known probed");
    peerman.FinalizeNode(height_zero);

    NeutralizeUnconnectedHeaders(chainman);
    peerman.ResetMatMulVerifyAdmissionForTest();
}

BOOST_AUTO_TEST_SUITE_END()

// Fresh RegTestingSetup is genesis (tip=0), matching the 2026-08-26 field
// stall. The shared peerman_tests suite above is not tip=0 once earlier
// cases have mined. Do not call ResetSharedPeermanFixture here: that helper
// requires a finished-IBD latch.
BOOST_FIXTURE_TEST_SUITE(peerman_trusted_mirror_bootstrap_tests, RegTestingSetup)

// PR 124 / MendeMatthias 2026-08-26. This is the field deadlock, not a
// truth table over WeakSubjectivityBootstrapHeight /
// TrustedMirrorSeedRaisesBestKnown /
// TrustedMirrorIgnoreNonAuthorityInboundHeaders. Those predicates were
// all individually fine. The stall was the INTERACTION:
//   1. NODE_MATMUL_ATTESTATION_ARCHIVE peers answer getheaders with
//      zero bytes,
//   2. NODE_MATMUL_CONSENSUS peers serve HEADERS which
//      ShouldIgnoreNonAuthorityInboundHeaders must ACCEPT below the
//      bootstrap pin (treating HEADERS like BLOCK drops them),
//   3. MaybeSeedGpuSignedFrontierBestKnown then used to assign
//      pindexBestKnownBlock = seed unconditionally, pinning BestKnown
//      to the local signed-frontier height so peer_best_ahead ==
//      best_header_ahead and in_flight=0.
// Reverting only (2) or only (3) restores the stall while the
// predicate tests in matmul_trusted_mirror_tests.cpp still pass.
BOOST_AUTO_TEST_CASE(fresh_mirror_deadlock_empty_archive_consensus_headers_and_raise_only_bestknown)
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
        std::move(config), /*trusted_mirror=*/true, /*serve=*/false,
        std::chrono::milliseconds{50}, error));
    BOOST_REQUIRE(node::matmul_trusted::IsTrustedMirror());
    struct MirrorReset {
        ~MirrorReset() { node::matmul_trusted::ResetForTest(); }
    } mirror_reset;

    ChainstateManager& chainman{*Assert(m_node.chainman)};
    PeerManager& peerman{*Assert(m_node.peerman)};
    ConnmanTestMsg& connman{static_cast<ConnmanTestMsg&>(*m_node.connman)};
    const CBlockIndex* genesis{
        WITH_LOCK(::cs_main, return chainman.ActiveChain().Tip())};
    BOOST_REQUIRE(genesis != nullptr);
    BOOST_REQUIRE_EQUAL(genesis->nHeight, 0);
    const int bootstrap_ceiling{node::matmul_trusted::WeakSubjectivityBootstrapHeight(
        chainman.GetParams().Checkpoints().GetHeight(),
        chainman.GetParams().HighestAssumeutxoHeight())};
    BOOST_REQUIRE_LT(genesis->nHeight, bootstrap_ceiling);
    peerman.SetBestBlock(genesis->nHeight,
                         std::chrono::seconds{genesis->GetBlockTime()});
    SetMockTime(std::chrono::seconds{genesis->GetBlockTime() + 3600});

    auto make_indexed_header = [&](const CBlockIndex& prev, unsigned int tag) {
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
    auto make_unindexed_header = [&](const uint256& prev_hash, int prev_height,
                                     int64_t prev_time, uint32_t nBits,
                                     int64_t mtp, unsigned int tag) {
        CBlock block;
        block.SetNull();
        block.hashPrevBlock = prev_hash;
        block.hashMerkleRoot = uint256::FromHex(
            std::string(60, '0') + strprintf("%04x", tag)).value();
        block.nTime = prev_time + 1;
        block.nBits = nBits;
        block.nVersion = VERSIONBITS_TOP_BITS;
        BOOST_REQUIRE(MineHeaderForConsensus(
            block, prev_height + 1, chainman.GetConsensus(), 5'000'000, mtp));
        return block;
    };

    // Local signed frontier at height 3 (field: 2000). HEADER_ONLY in the
    // index so MaybeSeedGpuSignedFrontierBestKnown has a seed to pin to.
    const CBlockIndex* walk{genesis};
    CBlockIndex* frontier{nullptr};
    for (int i = 0; i < 3; ++i) {
        frontier = make_indexed_header(*walk, 0xa10u + static_cast<unsigned int>(i));
        walk = frontier;
    }
    BOOST_REQUIRE(frontier != nullptr);
    BOOST_REQUIRE_EQUAL(frontier->nHeight, 3);
    BOOST_REQUIRE(node::matmul_trusted::SignAuthoritative(
                      frontier->GetBlockHash(), frontier->nHeight) ==
                  matmul::trusted::AddResult::Accepted);
    node::matmul_trusted::NoteAcceptedAttestationHeight(
        frontier->nHeight, frontier->GetBlockHash());

    constexpr int kAdvertisedHeight{10};
    std::vector<CBlock> consensus_headers;
    uint256 prev_hash{frontier->GetBlockHash()};
    int prev_height{frontier->nHeight};
    int64_t prev_time{frontier->GetBlockTime()};
    const uint32_t nBits{frontier->nBits};
    const int64_t mtp{frontier->GetMedianTimePast()};
    for (int h = 4; h <= kAdvertisedHeight; ++h) {
        consensus_headers.push_back(make_unindexed_header(
            prev_hash, prev_height, prev_time, nBits, mtp,
            0xc00u + static_cast<unsigned int>(h)));
        prev_hash = consensus_headers.back().GetHash();
        prev_height = h;
        prev_time = consensus_headers.back().nTime;
    }
    BOOST_REQUIRE_EQUAL(consensus_headers.size(), 7U);
    const uint256 last_hash{consensus_headers.back().GetHash()};
    BOOST_REQUIRE(WITH_LOCK(
        ::cs_main,
        return chainman.m_blockman.LookupBlockIndex(last_hash) == nullptr));

    const ServiceFlags archive_services{ServiceFlags(
        NODE_NETWORK | NODE_WITNESS | NODE_MATMUL_ATTESTATION_ARCHIVE |
        NODE_MATMUL_TRUSTED_MIRROR)};
    const ServiceFlags consensus_services{ServiceFlags(
        NODE_NETWORK | NODE_WITNESS | NODE_MATMUL_CONSENSUS)};
    CNode archive{/*id=*/701, /*sock=*/nullptr, CAddress{},
                  /*nKeyedNetGroupIn=*/0, /*nLocalHostNonceIn=*/0,
                  CAddress{}, /*addrNameIn=*/"bootstrap-empty-archive",
                  ConnectionType::OUTBOUND_FULL_RELAY,
                  /*inbound_onion=*/false, /*network_key=*/0};
    CNode consensus{/*id=*/702, /*sock=*/nullptr, CAddress{},
                    /*nKeyedNetGroupIn=*/1, /*nLocalHostNonceIn=*/0,
                    CAddress{}, /*addrNameIn=*/"bootstrap-consensus-headers",
                    ConnectionType::INBOUND,
                    /*inbound_onion=*/false, /*network_key=*/0};
    connman.Handshake(archive, /*successfully_connected=*/true,
                      archive_services, archive_services, PROTOCOL_VERSION,
                      /*relay_txs=*/true, /*starting_height=*/kAdvertisedHeight);
    connman.Handshake(consensus, /*successfully_connected=*/true,
                      consensus_services, consensus_services, PROTOCOL_VERSION,
                      /*relay_txs=*/true, /*starting_height=*/kAdvertisedHeight);
    BOOST_REQUIRE(!archive.fDisconnect);
    BOOST_REQUIRE(!consensus.fDisconnect);
    connman.AddTestNode(archive);
    connman.AddTestNode(consensus);
    connman.FlushSendBuffer(archive);
    connman.FlushSendBuffer(consensus);
    struct FinalizeBootstrap {
        PeerManager& peerman;
        ConnmanTestMsg& connman;
        CNode& archive;
        CNode& consensus;
        ~FinalizeBootstrap()
        {
            peerman.FinalizeNode(archive);
            peerman.FinalizeNode(consensus);
            connman.RemoveTestNode(archive);
            connman.RemoveTestNode(consensus);
        }
    } finalize{peerman, connman, archive, consensus};

    // (1) Archives serve nothing — the field getheaders zero-byte reply.
    std::vector<CBlock> empty;
    BOOST_REQUIRE(connman.ReceiveMsgFrom(
        archive, NetMsg::Make(NetMsgType::HEADERS, TX_WITH_WITNESS(empty))));
    archive.fPauseSend = false;
    (void)connman.ProcessMessagesOnce(archive);

    // (2) CONSENSUS HEADERS must be accepted via
    // ShouldIgnoreNonAuthorityInboundHeaders, not dropped as BLOCK.
    BOOST_REQUIRE(connman.ReceiveMsgFrom(
        consensus,
        NetMsg::Make(NetMsgType::HEADERS, TX_WITH_WITNESS(consensus_headers))));
    consensus.fPauseSend = false;
    (void)connman.ProcessMessagesOnce(consensus);

    const CBlockIndex* indexed{WITH_LOCK(
        ::cs_main, return chainman.m_blockman.LookupBlockIndex(last_hash))};
    BOOST_REQUIRE_MESSAGE(
        indexed != nullptr,
        "CONSENSUS HEADERS below the bootstrap pin must be indexed; "
        "reverting ShouldIgnoreNonAuthorityInboundHeaders to the BLOCK "
        "predicate restores the 2026-08-26 deadlock");
    BOOST_CHECK_EQUAL(indexed->nHeight, kAdvertisedHeight);
    BOOST_CHECK_EQUAL(
        WITH_LOCK(::cs_main, return chainman.m_best_header->nHeight),
        kAdvertisedHeight);

    CNodeStateStats after_headers;
    BOOST_REQUIRE(peerman.GetNodeStateStats(consensus.GetId(), after_headers));
    BOOST_CHECK_EQUAL(after_headers.nSyncHeight, kAdvertisedHeight);

    // (3) Seeding pindexBestKnownBlock from the local frontier must not
    // lower this peer's already-higher BestKnown.
    BOOST_CHECK(peerman.SendMessages(&consensus));
    CNodeStateStats after_seed;
    BOOST_REQUIRE(peerman.GetNodeStateStats(consensus.GetId(), after_seed));
    BOOST_CHECK_EQUAL(after_seed.nSyncHeight, kAdvertisedHeight);
    BOOST_CHECK_NE(after_seed.nSyncHeight, frontier->nHeight);

    BOOST_CHECK(peerman.SendMessages(&archive));
    CNodeStateStats archive_after;
    BOOST_REQUIRE(peerman.GetNodeStateStats(archive.GetId(), archive_after));
    // Stall shape was tip=0, best_header_ahead==peer_best_ahead==frontier,
    // in_flight=0. After the interaction, BestKnown stays at the advertised
    // height and a download is actually in flight.
    BOOST_CHECK_NE(archive_after.nSyncHeight, frontier->nHeight);
    BOOST_REQUIRE_MESSAGE(
        !after_seed.vHeightInFlight.empty() ||
            !archive_after.vHeightInFlight.empty(),
        "in_flight=0 with BestKnown pinned to the local frontier is the "
        "field stall; the node must request at least one body");

    peerman.ResetMatMulVerifyAdmissionForTest();
}

BOOST_AUTO_TEST_SUITE_END()
