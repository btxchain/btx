// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2022 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_NET_PROCESSING_H
#define BITCOIN_NET_PROCESSING_H

#include <net.h>
#include <node/protocol_version.h>
#include <threadsafety.h>
#include <txorphanage.h>
#include <validationinterface.h>

#include <chrono>
#include <functional>
#include <optional>

class AddrMan;
class CBlock;
class CChainParams;
class CTxMemPool;
class ChainstateManager;
class uint256;

namespace Dandelion { class DandelionManager; }

namespace node {
class AttestedUTXOSnapshotP2P;
class Warnings;
} // namespace node

/** Whether transaction reconciliation protocol should be enabled by default. */
static constexpr bool DEFAULT_TXRECONCILIATION_ENABLE{false};
/** Default for -maxorphantx, maximum number of orphan transactions kept in memory.
 *  Raised from 100 to 200 to accommodate PQ transactions with larger witness data. */
static const uint32_t DEFAULT_MAX_ORPHAN_TRANSACTIONS{200};
static constexpr size_t BLOCK_RECONSTRUCTION_EXTRA_TXN_PER_TXN_SIZE_LIMIT{100000};
static const size_t DEFAULT_BLOCK_RECONSTRUCTION_EXTRA_TXN_SIZE{10000000};
/** Default number of non-mempool transactions to keep around for block reconstruction. Includes
    orphan, replaced, and rejected transactions. */
static const uint32_t DEFAULT_BLOCK_RECONSTRUCTION_EXTRA_TXN{32768};
static const bool DEFAULT_PEERBLOOMFILTERS = false;
static const bool DEFAULT_PEERBLOCKFILTERS = false;
/** Maximum number of outstanding CMPCTBLOCK requests for the same block. */
static const unsigned int MAX_CMPCTBLOCKS_INFLIGHT_PER_BLOCK = 3;
/** Number of headers sent in one getheaders result. We rely on the assumption that if a peer sends
 *  less than this number, we reached its tip. Changing this value is a protocol upgrade. */
static const unsigned int MAX_HEADERS_RESULTS = 2000;
/** Maximum shielded transaction payload relay rate per peer (bytes/second). */
static constexpr size_t MAX_SHIELDED_TX_RELAY_BYTES_PER_SECOND{500'000};
/** Maximum getshieldeddata requests accepted per peer each second. */
static constexpr size_t MAX_SHIELDEDDATA_REQUESTS_PER_SECOND{8};

/** Whether scarce per-peer block-download capacity may be assigned to the
 * assumeutxo background chain. The active snapshot chain must first be out of
 * IBD and within one block of the best known header; the IBD latch alone can
 * clear based on chainwork and tip age while a fresh snapshot is still behind. */
constexpr bool ShouldFetchBackgroundSnapshotBlocks(
    bool background_sync,
    bool limited_peer,
    bool initial_block_download,
    int active_height,
    int best_header_height)
{
    return background_sync && !limited_peer && !initial_block_download &&
        best_header_height >= 0 && active_height >= best_header_height - 1;
}

/** Whether a connected peer remains eligible for block/header synchronization
 * once RC consensus-tier preference becomes active. This is evaluated at each
 * selection, rather than only at VERSION time, so a pre-activation preferred
 * peer cannot remain sticky across the activation boundary. */
constexpr bool IsMatMulPeerEligibleForSync(
    bool require_matmul_consensus,
    ServiceFlags services,
    bool has_noban_permission)
{
    return !require_matmul_consensus ||
        (services & NODE_MATMUL_CONSENSUS) == NODE_MATMUL_CONSENSUS ||
        has_noban_permission;
}

/** Whether this SendMessages pass may allocate block-download work to a peer.
 *
 * Production call sites pass peer_is_eligible=true: the MatMul consensus tier
 * is a PREFERENCE (fPreferredDownload), never a getdata gate. The parameter
 * remains so unit tests can assert the helper's combinatorial shape without
 * regressing the preference-only call site. */
constexpr bool ShouldRequestBlocksFromMatMulPeer(
    bool can_serve_blocks,
    bool peer_is_eligible,
    bool request_window_open,
    bool sync_blocks_and_headers_from_peer,
    bool limited_peer,
    bool initial_block_download,
    size_t blocks_in_flight,
    size_t max_blocks_in_flight)
{
    return can_serve_blocks && peer_is_eligible && request_window_open &&
        ((sync_blocks_and_headers_from_peer && !limited_peer) ||
         !initial_block_download) &&
        blocks_in_flight < max_blocks_in_flight;
}

struct MatMulPreferredDownloadReconcileResult {
    bool removed{false};
    bool counter_inconsistent{false};
};

/** Reconcile VERSION-time preferred-download state with the current dynamic
 * MatMul consensus-tier requirement. A non-positive aggregate counter is
 * clamped for the caller to recompute from peer state under cs_main. */
constexpr MatMulPreferredDownloadReconcileResult
ReconcileMatMulPreferredDownloadForSync(
    bool& preferred_download,
    int& preferred_download_count,
    bool peer_is_eligible)
{
    if (!preferred_download || peer_is_eligible) return {};
    preferred_download = false;
    if (preferred_download_count > 0) {
        --preferred_download_count;
        return {.removed = true};
    }
    preferred_download_count = 0;
    return {.removed = true, .counter_inconsistent = true};
}

struct CNodeStateStats {
    int nSyncHeight = -1;
    int nCommonHeight = -1;
    int m_starting_height = -1;
    std::chrono::microseconds m_ping_wait;
    std::vector<int> vHeightInFlight;
    bool m_relay_txs;
    CAmount m_fee_filter_received;
    uint64_t m_addr_processed = 0;
    uint64_t m_addr_rate_limited = 0;
    bool m_addr_relay_enabled{false};
    uint64_t m_shielded_tx_rate_limited{0};
    uint64_t m_shielded_data_rate_limited{0};
    ServiceFlags their_services;
    int64_t presync_height{-1};
    std::chrono::seconds time_offset{0};
    NodeSeconds m_last_block_announcement;
    int m_misbehavior_score{0};
    /** Best-known block hash/work for this peer, or empty when unknown.
     *  Height-only inference is intentionally not used (issue #108). */
    std::string m_best_known_block_hash;
    std::string m_best_known_block_work;
    uint64_t m_dup_header_bytes{0};
    uint32_t m_dup_header_msgs{0};
    uint64_t m_dup_header_skipped_bytes{0};
    std::string m_dup_header_action{"none"};
    /** Internal synchronization-selection snapshots used by regression tests. */
    bool m_preferred_download{false};
    int m_total_preferred_download_peer_count{0};
    bool m_headers_sync_started{false};
    int m_total_headers_sync_peer_count{0};
    bool m_chain_sync_protected{false};
    int m_total_chain_sync_protected_peer_count{0};
};

struct PeerManagerInfo {
    std::chrono::seconds median_outbound_time_offset{0s};
    bool ignores_incoming_txs{false};
    int min_smile_v2_version{MIN_SMILE_V2_PROTOCOL_VERSION};
    int smile_v2_enforcement_height{SMILE_V2_ENFORCEMENT_HEIGHT};
    int min_matmul_rc_version{MIN_MATMUL_RC_PROTOCOL_VERSION};
    int matmul_rc_enforcement_height{MATMUL_RC_ENFORCEMENT_HEIGHT};
};

class PeerManager : public CValidationInterface, public NetEventsInterface
{
public:
    struct Options {
        //! Whether this node is running in -blocksonly mode
        bool ignore_incoming_txs{DEFAULT_BLOCKSONLY};
        //! Whether transaction reconciliation protocol is enabled
        bool reconcile_txs{DEFAULT_TXRECONCILIATION_ENABLE};
        //! Maximum number of orphan transactions kept in memory
        uint32_t max_orphan_txs{DEFAULT_MAX_ORPHAN_TRANSACTIONS};
        //! Number of non-mempool transactions to keep around for block reconstruction. Includes
        //! orphan, replaced, and rejected transactions.
        uint32_t max_extra_txs{DEFAULT_BLOCK_RECONSTRUCTION_EXTRA_TXN};
        size_t max_extra_txs_size{DEFAULT_BLOCK_RECONSTRUCTION_EXTRA_TXN_SIZE};
        //! Whether all P2P messages are captured to disk
        bool capture_messages{false};
        //! Whether or not the internal RNG behaves deterministically (this is
        //! a test-only option).
        bool deterministic_rng{false};
        //! Number of headers sent in one getheaders message result (this is
        //! a test-only option).
        uint32_t max_headers_result{MAX_HEADERS_RESULTS};
        //! Minimum protocol version required for SMILE v2 shielded transactions.
        //! Peers below this version are disconnected once the chain tip is past
        //! smile_v2_enforcement_height. Overridable via -minsmilev2version.
        int min_smile_v2_version{MIN_SMILE_V2_PROTOCOL_VERSION};
        //! Chain height at which SMILE v2 protocol version enforcement activates.
        int smile_v2_enforcement_height{SMILE_V2_ENFORCEMENT_HEIGHT};
        //! Minimum protocol version required to follow the MatMul v4.7 Epoch-A
        //! chain. Peers below this are disconnected once the tip is past
        //! matmul_rc_enforcement_height. Overridable via -minmatmulrcversion.
        int min_matmul_rc_version{MIN_MATMUL_RC_PROTOCOL_VERSION};
        //! Chain height at which Epoch-A protocol version enforcement activates.
        //! Default MATMUL_RC_ENFORCEMENT_HEIGHT is INT32_MAX (off). Overridable
        //! via -matmulrcenforcementheight.
        int matmul_rc_enforcement_height{MATMUL_RC_ENFORCEMENT_HEIGHT};
        //! WP-7 / C5: whether the v4.4 ENC-DR reference recompute for P2P block
        //! deliveries may run on a bounded off-thread worker pool instead of the
        //! message-handler thread. Only effective when the MatMul v4 fork height
        //! is finite (nMatMulV4Height != INT32_MAX); kill-switch:
        //! -matmulasyncverify=0.
        bool matmul_async_verify{true};
        //! Start digest-only RC ExactReplay from an admitted near-tip header.
        bool matmul_rc_header_first{true};
        //! Require the Poseidon2 rcadmit sidecar before an untrusted P2P peer
        //! can consume an RC ExactReplay slot.
        bool matmul_rc_admission{true};
        //! Relay at most a small authenticated-tip-child candidate set while
        //! ExactReplay is pending; never grants chainwork or mining eligibility.
        bool matmul_rc_provisional_relay{true};
    };

    static std::unique_ptr<PeerManager> make(CConnman& connman, AddrMan& addrman,
                                             BanMan* banman, ChainstateManager& chainman,
                                             CTxMemPool& pool, node::Warnings& warnings, Options opts);
    virtual ~PeerManager() = default;

    /**
     * Attempt to manually fetch block from a given peer.
     *
     * @param[in]  peer_id      The peer id
     * @param[in]  block_index  The blockindex
     * @returns std::nullopt if a request was successfully made, otherwise an error message
     */
    std::optional<std::string> FetchBlock(NodeId peer_id, const CBlockIndex& block_index);
    virtual std::optional<std::string> FetchBlock(NodeId peer_id, const uint256& hash, const CBlockIndex* block_index) = 0;

    /** Begin running background tasks, should only be called once */
    virtual void StartScheduledTasks(CScheduler& scheduler) = 0;

    /**
     * Join the MatMul verify worker while the validation scheduler is still
     * running. In-flight completions call ProcessBlockSync / ActivateBestChain,
     * which drain the scheduler queue. Stopping the scheduler first deadlocks
     * b-shutoff vs b-mmverify and skips PersistShieldedState.
     */
    virtual void StopBackgroundWorkers() = 0;

    /** Get statistics from node state */
    virtual bool GetNodeStateStats(NodeId nodeid, CNodeStateStats& stats) const = 0;
    virtual void LimitOrphanTxSize(uint32_t nMaxOrphans) = 0;

    virtual std::vector<TxOrphanage::OrphanTxBase> GetOrphanTransactions() = 0;

    /** Get peer manager info. */
    virtual PeerManagerInfo GetInfo() const = 0;

    /** Relay transaction to all peers. */
    virtual void RelayTransaction(const uint256& txid, const uint256& wtxid) = 0;

    /** Set the Dandelion++ manager (owned by NodeContext). */
    virtual void SetDandelionManager(Dandelion::DandelionManager* mgr) = 0;

    /** Send ping message to all peers */
    virtual void SendPings() = 0;

    /** Set the height of the best block and its time (seconds since epoch). */
    virtual void SetBestBlock(int height, std::chrono::seconds time) = 0;

    /* Public for unit testing. */
    virtual void UnitTestMisbehaving(NodeId peer_id) = 0;

    /** Stall ExactReplay in peerman tests so a header-first job occupies the
     *  cap-one lease long enough for a subsequent body to take the handoff
     *  path. No-op when the async worker was not constructed. */
    virtual void InstallMatMulVerifyOverrideForTest(
        std::function<bool(const CBlock&, int32_t, std::optional<int64_t>)> verify) = 0;
    /** Drop leftover speculative/pending ExactReplay leases between cases that
     *  share one RegTestingSetup. */
    virtual void ResetMatMulVerifyAdmissionForTest() = 0;
    /** True while a complete body is held for scheduler re-admission. */
    [[nodiscard]] virtual bool HasMatMulRetainedBodyForTest(const uint256& hash) const = 0;
    [[nodiscard]] virtual bool UnitTestHasMatMulRetainedBody(const uint256& hash) const = 0;

    /**
     * Evict extra outbound peers. If we think our tip may be stale, connect to an extra outbound.
     * Public for unit testing.
     */
    virtual void CheckForStaleTipAndEvictPeers() = 0;

    /** Process a single message from a peer. Public for fuzz testing */
    virtual void ProcessMessage(CNode& pfrom, const std::string& msg_type, DataStream& vRecv,
                                const std::chrono::microseconds time_received, const std::atomic<bool>& interruptMsgProc) EXCLUSIVE_LOCKS_REQUIRED(g_msgproc_mutex) = 0;

    /** Peers advertising NODE_ATTESTED_UTXO_SNAPSHOT. */
    [[nodiscard]] virtual std::vector<NodeId> GetAttestedUTXOSnapshotPeers() const = 0;
    /** Send getutxomanif to peer (block_hash null = any offer). */
    [[nodiscard]] virtual bool RequestAttestedUTXOManifest(NodeId peer_id, const uint256& block_hash) = 0;
    /** Send getutxochunk to peer. */
    [[nodiscard]] virtual bool RequestAttestedUTXOChunk(NodeId peer_id, const uint256& block_hash, uint32_t chunk_index) = 0;
    /** Coordinator owned by this peer-manager/node instance. */
    [[nodiscard]] virtual node::AttestedUTXOSnapshotP2P&
    AttestedUTXOSnapshotCoordinator() = 0;

    /** This function is used for testing the stale tip eviction logic, see denialofservice_tests.cpp */
    virtual void UpdateLastBlockAnnounceTime(NodeId node, int64_t time_in_seconds) = 0;

    /**
     * Gets the set of service flags which are "desirable" for a given peer.
     *
     * These are the flags which are required for a peer to support for them
     * to be "interesting" to us, ie for us to wish to use one of our few
     * outbound connection slots for or for us to wish to prioritize keeping
     * their connection around.
     *
     * Relevant service flags may be peer- and state-specific in that the
     * version of the peer may determine which flags are required (eg in the
     * case of NODE_NETWORK_LIMITED where we seek out NODE_NETWORK peers
     * unless they set NODE_NETWORK_LIMITED and we are out of IBD, in which
     * case NODE_NETWORK_LIMITED suffices).
     *
     * Thus, generally, avoid calling with 'services' == NODE_NONE, unless
     * state-specific flags must absolutely be avoided. When called with
     * 'services' == NODE_NONE, the returned desirable service flags are
     * guaranteed to not change dependent on state - ie they are suitable for
     * use when describing peers which we know to be desirable, but for which
     * we do not have a confirmed set of service flags.
    */
    virtual ServiceFlags GetDesirableServiceFlags(ServiceFlags services) const = 0;

    /** Get number of peers from which we're downloading blocks */
    virtual int GetNumberOfPeersWithValidatedDownloads() const EXCLUSIVE_LOCKS_REQUIRED(::cs_main) = 0;
};

#endif // BITCOIN_NET_PROCESSING_H
