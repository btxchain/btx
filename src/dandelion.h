// Copyright (c) 2024-present The BTX Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_DANDELION_H
#define BITCOIN_DANDELION_H

#include <common/bloom.h>
#include <net.h>
#include <primitives/transaction.h>
#include <sync.h>
#include <span.h>
#include <uint256.h>
#include <util/time.h>

#include <chrono>
#include <map>
#include <optional>
#include <random>
#include <unordered_map>
#include <vector>

class CConnman;
class CScheduler;

namespace Dandelion {

// Protocol constants
static constexpr int MAX_DESTINATIONS = 4;
static constexpr size_t SOURCE_RELAY_POOL_SIZE = 2;
static constexpr double STEM_PROBABILITY = 0.9;
static constexpr std::chrono::seconds EPOCH_INTERVAL{600};
static constexpr std::chrono::seconds EPOCH_MIN{60};
static constexpr std::chrono::seconds EMBARGO_MEAN{39};
static constexpr std::chrono::seconds EMBARGO_MIN{5};
static constexpr std::chrono::seconds EMBARGO_MAX{180};
static constexpr std::chrono::seconds MONITOR_INTERVAL{5};
// Rate limiting / DoS protection
static constexpr size_t MAX_STEM_TXS_PER_PEER = 100;
static constexpr size_t MAX_STEM_BYTES_PER_PEER = 5 * 1024 * 1024;
static constexpr size_t MAX_STEMPOOL_SIZE = 300;
static constexpr size_t MAX_STEMPOOL_BYTES = 15 * 1024 * 1024;
static constexpr unsigned int STEM_SEEN_FILTER_SIZE = 50000;
static constexpr double STEM_SEEN_FP_RATE = 0.000001;

struct StemPoolEntry {
    CTransactionRef tx;
    NodeId from_peer;
    std::chrono::seconds embargo_deadline;
    std::chrono::seconds arrival_time;
    size_t tx_size;

    StemPoolEntry(CTransactionRef tx_in, NodeId from, std::chrono::seconds deadline,
                  std::chrono::seconds arrival, size_t size)
        : tx(std::move(tx_in)), from_peer(from), embargo_deadline(deadline),
          arrival_time(arrival), tx_size(size) {}
};

struct StemPeerState {
    size_t stem_tx_count{0};
    size_t stem_bytes{0};

    bool CanAcceptStem(size_t tx_size) const {
        return stem_tx_count < MAX_STEM_TXS_PER_PEER &&
               stem_bytes + tx_size <= MAX_STEM_BYTES_PER_PEER;
    }

    void RecordStem(size_t tx_size) {
        ++stem_tx_count;
        stem_bytes += tx_size;
    }
};

struct RelayAssignment {
    std::vector<NodeId> relay_pool;
    NodeId last_selected{-1};

    [[nodiscard]] bool Empty() const {
        return relay_pool.empty();
    }
};

class DandelionManager {
public:
    enum class AcceptResult {
        ACCEPTED,
        FLUFF_IMMEDIATELY,
        ALREADY_KNOWN,
        RATE_LIMITED,
        STEMPOOL_FULL,
    };

    DandelionManager();

    void Initialize(CConnman* connman) EXCLUSIVE_LOCKS_REQUIRED(!m_mutex);

    void MaybeRotateEpoch() EXCLUSIVE_LOCKS_REQUIRED(!m_mutex);
    void ForceRotateEpoch() EXCLUSIVE_LOCKS_REQUIRED(!m_mutex);

    std::pair<AcceptResult, std::optional<NodeId>>
    AcceptStemTransaction(const CTransactionRef& tx, NodeId from_peer, size_t tx_size)
        EXCLUSIVE_LOCKS_REQUIRED(!m_mutex);

    bool HaveStemTx(const uint256& hash) const EXCLUSIVE_LOCKS_REQUIRED(!m_mutex);

    /** Check if a transaction is currently in the stempool (not bloom filter).
     *  Unlike HaveStemTx, this does not match transactions that have already
     *  left the stempool but remain in the bloom filter. */
    bool IsInStemPool(const uint256& hash) const EXCLUSIVE_LOCKS_REQUIRED(!m_mutex);

    CTransactionRef RemoveFromStemPool(const uint256& txid) EXCLUSIVE_LOCKS_REQUIRED(!m_mutex);

    std::vector<CTransactionRef> CheckEmbargoes() EXCLUSIVE_LOCKS_REQUIRED(!m_mutex);

    void TxAddedToMempool(const uint256& txid) EXCLUSIVE_LOCKS_REQUIRED(!m_mutex);

    bool IsActive(int current_height) const;

    std::optional<NodeId> GetRelayDestination(NodeId from_peer) const EXCLUSIVE_LOCKS_REQUIRED(!m_mutex);

    size_t GetStemPoolSize() const EXCLUSIVE_LOCKS_REQUIRED(!m_mutex);
    size_t GetStemPoolBytes() const EXCLUSIVE_LOCKS_REQUIRED(!m_mutex);
    bool IsInStemMode() const EXCLUSIVE_LOCKS_REQUIRED(!m_mutex);
    std::vector<NodeId> GetRelayPeers() const EXCLUSIVE_LOCKS_REQUIRED(!m_mutex);

    void PeerDisconnected(NodeId peer_id) EXCLUSIVE_LOCKS_REQUIRED(!m_mutex);

private:
    mutable Mutex m_mutex;
    CConnman* m_connman GUARDED_BY(m_mutex){nullptr};

    bool m_stem_mode GUARDED_BY(m_mutex){true};
    std::chrono::seconds m_epoch_deadline GUARDED_BY(m_mutex){0s};
    std::vector<NodeId> m_relay_destinations GUARDED_BY(m_mutex);

    std::map<NodeId, RelayAssignment> m_route_table GUARDED_BY(m_mutex);

    std::map<uint256, StemPoolEntry> m_stempool GUARDED_BY(m_mutex);
    size_t m_stempool_bytes GUARDED_BY(m_mutex){0};

    CRollingBloomFilter m_stem_seen_filter GUARDED_BY(m_mutex);

    // Transactions evicted from the stempool that should be fluffed on the
    // next CheckEmbargoes() call rather than silently dropped.
    // Bounded to MAX_STEMPOOL_SIZE to prevent unbounded growth.
    std::vector<CTransactionRef> m_pending_fluff GUARDED_BY(m_mutex);

    // Local wallet transactions keep a bounded relay pool within an epoch
    // instead of pinning to one relay or spraying across the entire set.
    RelayAssignment m_local_assignment GUARDED_BY(m_mutex);

    std::unordered_map<NodeId, StemPeerState> m_peer_state GUARDED_BY(m_mutex);

    std::mt19937_64 m_rng GUARDED_BY(m_mutex);
    uint64_t m_epoch_route_nonce GUARDED_BY(m_mutex){0};

    void SelectNewRelays() EXCLUSIVE_LOCKS_REQUIRED(m_mutex);
    void RotateEpochInternal() EXCLUSIVE_LOCKS_REQUIRED(m_mutex);
    std::chrono::seconds ComputeNextEpochDuration() EXCLUSIVE_LOCKS_REQUIRED(m_mutex);
    std::chrono::seconds ComputeEmbargoDeadline() EXCLUSIVE_LOCKS_REQUIRED(m_mutex);
    NodeId SelectRelayDestination(NodeId from_peer, const uint256& txid) EXCLUSIVE_LOCKS_REQUIRED(m_mutex);
    RelayAssignment BuildRelayAssignment(int64_t route_key, Span<const NodeId> connected_relays) EXCLUSIVE_LOCKS_REQUIRED(m_mutex);
    void ScrubDisconnectedRelayFromAssignments(NodeId peer_id) EXCLUSIVE_LOCKS_REQUIRED(m_mutex);
    bool IsRelayPeerConnected(NodeId peer_id) const EXCLUSIVE_LOCKS_REQUIRED(m_mutex);
    bool EvictStemPool(size_t needed_bytes) EXCLUSIVE_LOCKS_REQUIRED(m_mutex);
};

} // namespace Dandelion

#endif // BITCOIN_DANDELION_H
