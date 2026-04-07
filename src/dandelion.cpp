// Copyright (c) 2024-present The BTX Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <dandelion.h>

#include <chainparams.h>
#include <hash.h>
#include <logging.h>
#include <net.h>
#include <scheduler.h>
#include <util/time.h>

#include <algorithm>
#include <chrono>
#include <limits>
#include <random>
#include <set>

namespace Dandelion {
namespace {

[[nodiscard]] bool IsPreferredRelayConnection(const CNode& node)
{
    return node.IsFullOutboundConn() || node.IsBlockOnlyConn() || node.IsManualConn();
}

} // namespace

DandelionManager::DandelionManager()
    : m_stem_seen_filter(STEM_SEEN_FILTER_SIZE, STEM_SEEN_FP_RATE),
      m_rng(std::random_device{}())
{
}

void DandelionManager::Initialize(CConnman* connman)
{
    LOCK(m_mutex);
    m_connman = connman;
    // Set deadline to 0s so the first call to MaybeRotateEpoch() triggers rotation.
    m_epoch_deadline = std::chrono::seconds{0};
}

// ---------- Epoch management ----------

void DandelionManager::RotateEpochInternal()
{
    AssertLockHeld(m_mutex);

    // Decide stem vs fluff for this epoch.
    std::bernoulli_distribution stem_dist(STEM_PROBABILITY);
    m_stem_mode = stem_dist(m_rng);
    m_epoch_route_nonce = m_rng();

    SelectNewRelays();
    m_peer_state.clear();
    m_route_table.clear();
    m_local_assignment = {};
    m_epoch_deadline = GetTime<std::chrono::seconds>() + ComputeNextEpochDuration();
}

void DandelionManager::MaybeRotateEpoch()
{
    LOCK(m_mutex);
    const auto now = GetTime<std::chrono::seconds>();
    if (now < m_epoch_deadline) return;

    RotateEpochInternal();
    LogDebug(BCLog::DANDELION, "Dandelion++: new epoch, stem_mode=%d\n", m_stem_mode);
}

void DandelionManager::ForceRotateEpoch()
{
    LOCK(m_mutex);
    RotateEpochInternal();
    LogDebug(BCLog::DANDELION, "Dandelion++: forced epoch rotation, stem_mode=%d\n", m_stem_mode);
}

void DandelionManager::SelectNewRelays()
{
    AssertLockHeld(m_mutex);

    m_relay_destinations.clear();

    if (!m_connman) return;

    struct RelayCandidate {
        NodeId id;
        uint64_t netgroup;
    };

    std::vector<RelayCandidate> preferred_candidates;
    std::vector<RelayCandidate> fallback_candidates;
    std::vector<RelayCandidate> reserve_candidates;
    m_connman->ForEachNode([&](CNode* pnode) {
        if (!pnode->fSuccessfullyConnected) {
            return;
        }
        RelayCandidate candidate{pnode->GetId(), pnode->nKeyedNetGroup};
        if (IsPreferredRelayConnection(*pnode)) {
            if (pnode->m_supports_dandelion) {
                preferred_candidates.push_back(candidate);
            } else {
                fallback_candidates.push_back(candidate);
            }
        } else if (pnode->IsInboundConn() && pnode->m_supports_dandelion) {
            // Preserve a last-resort privacy path when no outbound-style relay
            // peers are available, but never prefer inbound peers ahead of
            // outbound/block-relay/manual candidates.
            reserve_candidates.push_back(candidate);
        }
    });

    std::vector<NodeId> selected_relays;
    selected_relays.reserve(MAX_DESTINATIONS);
    std::set<uint64_t> selected_groups;
    std::mt19937_64 rng = m_rng;

    auto select_candidates = [&](std::vector<RelayCandidate>& candidates) {
        std::shuffle(candidates.begin(), candidates.end(), rng);
        for (const auto& candidate : candidates) {
            if (selected_relays.size() >= static_cast<size_t>(MAX_DESTINATIONS)) break;
            if (selected_groups.insert(candidate.netgroup).second) {
                selected_relays.push_back(candidate.id);
            }
        }
    };

    select_candidates(preferred_candidates);
    if (selected_relays.size() < static_cast<size_t>(MAX_DESTINATIONS)) {
        select_candidates(reserve_candidates);
    }
    if (selected_relays.empty()) {
        select_candidates(fallback_candidates);
    }
    m_rng = std::move(rng);
    m_relay_destinations = std::move(selected_relays);

    LogDebug(BCLog::DANDELION, "Dandelion++: selected %d relay destination(s)\n", m_relay_destinations.size());
}

std::chrono::seconds DandelionManager::ComputeNextEpochDuration()
{
    AssertLockHeld(m_mutex);
    const int64_t mean_tail = std::max<int64_t>(1, EPOCH_INTERVAL.count() - EPOCH_MIN.count());
    std::exponential_distribution<double> dist(1.0 / static_cast<double>(mean_tail));
    double sample = dist(m_rng);
    const double bounded_sample = std::min(
        sample,
        static_cast<double>(std::numeric_limits<int64_t>::max() - EPOCH_MIN.count()));
    return EPOCH_MIN + std::chrono::seconds{static_cast<int64_t>(bounded_sample)};
}

std::chrono::seconds DandelionManager::ComputeEmbargoDeadline()
{
    AssertLockHeld(m_mutex);
    const auto now = GetTime<std::chrono::seconds>();
    std::exponential_distribution<double> dist(1.0 / static_cast<double>(EMBARGO_MEAN.count()));
    double sample = dist(m_rng);
    auto delay = std::chrono::seconds(static_cast<int64_t>(
        std::clamp(sample,
                   static_cast<double>(EMBARGO_MIN.count()),
                   static_cast<double>(EMBARGO_MAX.count()))));
    return now + delay;
}

// ---------- Route assignment ----------

NodeId DandelionManager::SelectRelayDestination(NodeId from_peer, const uint256& txid)
{
    AssertLockHeld(m_mutex);
    (void)txid;

    if (m_relay_destinations.empty()) {
        return -1; // No relay destinations; caller should fluff.
    }

    std::vector<NodeId> connected_relays;
    connected_relays.reserve(m_relay_destinations.size());
    for (const NodeId relay_id : m_relay_destinations) {
        if (IsRelayPeerConnected(relay_id)) {
            connected_relays.push_back(relay_id);
        }
    }
    if (connected_relays.empty()) {
        return -1;
    }

    auto prune_assignment = [&](RelayAssignment& assignment) {
        assignment.relay_pool.erase(
            std::remove_if(
                assignment.relay_pool.begin(),
                assignment.relay_pool.end(),
                [&](NodeId relay_id) {
                    return std::find(connected_relays.begin(), connected_relays.end(), relay_id) ==
                           connected_relays.end();
                       }),
            assignment.relay_pool.end());
        if (assignment.relay_pool.empty()) {
            assignment.last_selected = -1;
        } else if (std::find(assignment.relay_pool.begin(),
                             assignment.relay_pool.end(),
                             assignment.last_selected) == assignment.relay_pool.end()) {
            assignment.last_selected = -1;
        }
    };

    RelayAssignment* assignment{nullptr};
    if (from_peer == -1) {
        assignment = &m_local_assignment;
    } else {
        assignment = &m_route_table[from_peer];
    }
    prune_assignment(*assignment);
    if (assignment->relay_pool.empty()) {
        const int64_t route_key = from_peer == -1
            ? -1
            : static_cast<int64_t>(from_peer);
        *assignment = BuildRelayAssignment(route_key, connected_relays);
    }
    if (assignment->relay_pool.empty()) {
        return -1;
    }

    HashWriter hw;
    hw << m_epoch_route_nonce;
    hw << static_cast<int64_t>(from_peer);
    hw << txid;
    const uint256 route_hash = hw.GetSHA256();
    const uint64_t route_selector = ReadLE64(route_hash.begin());
    NodeId dest = assignment->relay_pool[route_selector % assignment->relay_pool.size()];
    assignment->last_selected = dest;
    return dest;
}

RelayAssignment DandelionManager::BuildRelayAssignment(int64_t route_key,
                                                       Span<const NodeId> connected_relays)
{
    AssertLockHeld(m_mutex);

    RelayAssignment assignment;
    if (connected_relays.empty()) {
        return assignment;
    }

    std::vector<std::pair<uint256, NodeId>> scored_relays;
    scored_relays.reserve(connected_relays.size());
    for (const NodeId relay_id : connected_relays) {
        HashWriter hw;
        hw << m_epoch_route_nonce;
        hw << route_key;
        hw << static_cast<int64_t>(relay_id);
        scored_relays.emplace_back(hw.GetSHA256(), relay_id);
    }
    std::sort(scored_relays.begin(),
              scored_relays.end(),
              [](const auto& lhs, const auto& rhs) {
                  return lhs.first < rhs.first;
              });

    const size_t pool_size = std::min(connected_relays.size(), SOURCE_RELAY_POOL_SIZE);
    assignment.relay_pool.reserve(pool_size);
    for (size_t i = 0; i < pool_size; ++i) {
        assignment.relay_pool.push_back(scored_relays[i].second);
    }
    return assignment;
}

bool DandelionManager::IsRelayPeerConnected(NodeId peer_id) const
{
    AssertLockHeld(m_mutex);
    if (!m_connman || peer_id == -1) return false;

    bool connected{false};
    m_connman->ForEachNode([&](CNode* pnode) {
        if (connected) return;
        if (pnode->GetId() == peer_id &&
            pnode->fSuccessfullyConnected &&
            (IsPreferredRelayConnection(*pnode) || pnode->IsInboundConn())) {
            connected = true;
        }
    });
    return connected;
}

std::optional<NodeId> DandelionManager::GetRelayDestination(NodeId from_peer) const
{
    LOCK(m_mutex);
    if (from_peer == -1) {
        if (IsRelayPeerConnected(m_local_assignment.last_selected)) {
            return m_local_assignment.last_selected;
        }
        return std::nullopt;
    }

    auto it = m_route_table.find(from_peer);
    if (it != m_route_table.end() &&
        IsRelayPeerConnected(it->second.last_selected)) {
        return it->second.last_selected;
    }
    return std::nullopt;
}

// ---------- Stempool management ----------

std::pair<DandelionManager::AcceptResult, std::optional<NodeId>>
DandelionManager::AcceptStemTransaction(const CTransactionRef& tx, NodeId from_peer, size_t tx_size)
{
    LOCK(m_mutex);

    const uint256& txid = tx->GetHash();

    // Already in stempool?
    if (m_stempool.contains(txid)) {
        return {AcceptResult::ALREADY_KNOWN, std::nullopt};
    }

    // Already seen in bloom filter? (covers txs that graduated to mempool or
    // were seen in a previous stem round).
    if (m_stem_seen_filter.contains(txid)) {
        return {AcceptResult::ALREADY_KNOWN, std::nullopt};
    }

    // Per-peer rate limiting (skip for local wallet txs).
    // Only check here; recording is deferred until the tx is actually
    // accepted so that STEMPOOL_FULL rejections don't penalise honest peers.
    if (from_peer != -1) {
        auto& ps = m_peer_state[from_peer];
        if (!ps.CanAcceptStem(tx_size)) {
            LogDebug(BCLog::DANDELION, "Dandelion++: rate-limiting stem tx %s.. from peer %d\n",
                     txid.ToString().substr(0, 12), from_peer);
            return {AcceptResult::RATE_LIMITED, std::nullopt};
        }
    }

    // Preserve local-wallet privacy by keeping self-originated transactions on
    // the stem path whenever a relay is available, even during fluff epochs.
    if (from_peer != -1 && !m_stem_mode) {
        m_stem_seen_filter.insert(txid);
        if (from_peer != -1) m_peer_state[from_peer].RecordStem(tx_size);
        return {AcceptResult::FLUFF_IMMEDIATELY, std::nullopt};
    }

    // Determine relay destination.
    NodeId dest = SelectRelayDestination(from_peer, txid);
    if (dest == -1) {
        SelectNewRelays();
        dest = SelectRelayDestination(from_peer, txid);
    }
    if (dest == -1) {
        // No outbound peers available; fall back to fluff.
        m_stem_seen_filter.insert(txid);
        if (from_peer != -1) m_peer_state[from_peer].RecordStem(tx_size);
        return {AcceptResult::FLUFF_IMMEDIATELY, std::nullopt};
    }

    // Evict if stempool is full.
    if (m_stempool.size() >= MAX_STEMPOOL_SIZE || m_stempool_bytes + tx_size > MAX_STEMPOOL_BYTES) {
        if (!EvictStemPool(tx_size)) {
            return {AcceptResult::STEMPOOL_FULL, std::nullopt};
        }
    }

    // Record rate-limit accounting now that the tx will be accepted.
    if (from_peer != -1) m_peer_state[from_peer].RecordStem(tx_size);

    // Compute embargo deadline and add to stempool.
    auto deadline = ComputeEmbargoDeadline();

    m_stempool.emplace(txid, StemPoolEntry(tx, from_peer, deadline,
                                           GetTime<std::chrono::seconds>(), tx_size));
    m_stempool_bytes += tx_size;
    m_stem_seen_filter.insert(txid);

    LogDebug(BCLog::DANDELION, "Dandelion++: accepted stem tx %s from peer %d, relay to %d, "
             "stempool size=%d\n",
             txid.ToString().substr(0, 12), from_peer, dest, m_stempool.size());

    return {AcceptResult::ACCEPTED, dest};
}

bool DandelionManager::HaveStemTx(const uint256& hash) const
{
    LOCK(m_mutex);
    return m_stempool.contains(hash) || m_stem_seen_filter.contains(hash);
}

bool DandelionManager::IsInStemPool(const uint256& hash) const
{
    LOCK(m_mutex);
    return m_stempool.contains(hash);
}

CTransactionRef DandelionManager::RemoveFromStemPool(const uint256& txid)
{
    LOCK(m_mutex);
    auto it = m_stempool.find(txid);
    if (it == m_stempool.end()) {
        return nullptr;
    }
    CTransactionRef tx = std::move(it->second.tx);
    if (it->second.tx_size <= m_stempool_bytes) {
        m_stempool_bytes -= it->second.tx_size;
    } else {
        m_stempool_bytes = 0;
    }
    m_stempool.erase(it);
    return tx;
}

std::vector<CTransactionRef> DandelionManager::CheckEmbargoes()
{
    LOCK(m_mutex);
    const auto now = GetTime<std::chrono::seconds>();
    std::vector<CTransactionRef> expired;

    auto it = m_stempool.begin();
    while (it != m_stempool.end()) {
        if (now >= it->second.embargo_deadline) {
            LogDebug(BCLog::DANDELION, "Dandelion++: embargo expired for tx %s.., fluffing\n",
                     it->first.ToString().substr(0, 12));
            expired.push_back(it->second.tx);
            if (it->second.tx_size <= m_stempool_bytes) {
                m_stempool_bytes -= it->second.tx_size;
            } else {
                m_stempool_bytes = 0;
            }
            it = m_stempool.erase(it);
        } else {
            ++it;
        }
    }

    // Also drain any transactions evicted from the stempool that need fluffing.
    if (!m_pending_fluff.empty()) {
        expired.insert(expired.end(),
                       std::make_move_iterator(m_pending_fluff.begin()),
                       std::make_move_iterator(m_pending_fluff.end()));
        m_pending_fluff.clear();
    }

    return expired;
}

void DandelionManager::TxAddedToMempool(const uint256& txid)
{
    LOCK(m_mutex);
    auto it = m_stempool.find(txid);
    if (it != m_stempool.end()) {
        if (it->second.tx_size <= m_stempool_bytes) {
            m_stempool_bytes -= it->second.tx_size;
        } else {
            m_stempool_bytes = 0;
        }
        m_stempool.erase(it);
        LogDebug(BCLog::DANDELION, "Dandelion++: tx %s.. graduated to mempool, removed from stempool\n",
                 txid.ToString().substr(0, 12));
    }
}

// ---------- Eviction ----------

bool DandelionManager::EvictStemPool(size_t needed_bytes)
{
    AssertLockHeld(m_mutex);

    if (m_stempool.empty()) {
        return false;
    }

    // Build a sorted index by arrival_time so eviction is O(n log n) total
    // instead of O(k * n) where k is the number of evictions needed.
    std::vector<std::map<uint256, StemPoolEntry>::iterator> by_arrival;
    by_arrival.reserve(m_stempool.size());
    for (auto it = m_stempool.begin(); it != m_stempool.end(); ++it) {
        by_arrival.push_back(it);
    }
    std::sort(by_arrival.begin(), by_arrival.end(),
              [](const auto& a, const auto& b) {
                  return a->second.arrival_time < b->second.arrival_time;
              });

    size_t idx = 0;
    while (m_stempool.size() >= MAX_STEMPOOL_SIZE ||
           m_stempool_bytes + needed_bytes > MAX_STEMPOOL_BYTES) {
        if (idx >= by_arrival.size()) {
            return false;
        }

        auto oldest = by_arrival[idx++];
        LogDebug(BCLog::DANDELION, "Dandelion++: evicting stem tx %s.. (arrival=%d), will fluff\n",
                 oldest->first.ToString().substr(0, 12), oldest->second.arrival_time.count());
        // Bound pending_fluff to prevent unbounded memory growth.
        if (m_pending_fluff.size() < MAX_STEMPOOL_SIZE) {
            m_pending_fluff.push_back(std::move(oldest->second.tx));
        }
        if (oldest->second.tx_size <= m_stempool_bytes) {
            m_stempool_bytes -= oldest->second.tx_size;
        } else {
            m_stempool_bytes = 0;
        }
        m_stempool.erase(oldest);
    }

    return true;
}

// ---------- Peer lifecycle ----------

void DandelionManager::PeerDisconnected(NodeId peer_id)
{
    LOCK(m_mutex);

    // Remove per-peer state.
    m_peer_state.erase(peer_id);

    // Remove any route table entries that pointed FROM this peer.
    m_route_table.erase(peer_id);
    ScrubDisconnectedRelayFromAssignments(peer_id);

    // Remove from relay destinations.
    auto rd_it = std::find(m_relay_destinations.begin(), m_relay_destinations.end(), peer_id);
    if (rd_it != m_relay_destinations.end()) {
        m_relay_destinations.erase(rd_it);
        LogDebug(BCLog::DANDELION, "Dandelion++: relay peer %d disconnected, %d relay(s) remaining\n",
                 peer_id, m_relay_destinations.size());

        // If no relay destinations remain, try to reseat them immediately so
        // existing stem entries do not all fluff at a single detectable
        // boundary.
        if (m_relay_destinations.empty()) {
            SelectNewRelays();
            if (m_relay_destinations.empty()) {
                LogDebug(BCLog::DANDELION,
                         "Dandelion++: no relay destinations remain, preserving embargoes until "
                         "their original deadlines rather than forcing immediate fluff\n");
            } else {
                LogDebug(BCLog::DANDELION,
                         "Dandelion++: reseated relay destinations after disconnect, %d relay(s) "
                         "available\n",
                         m_relay_destinations.size());
            }
        }
    }
}

void DandelionManager::ScrubDisconnectedRelayFromAssignments(NodeId peer_id)
{
    AssertLockHeld(m_mutex);

    auto scrub_assignment = [&](RelayAssignment& assignment) {
        assignment.relay_pool.erase(
            std::remove(assignment.relay_pool.begin(), assignment.relay_pool.end(), peer_id),
            assignment.relay_pool.end());
        if (assignment.relay_pool.empty()) {
            assignment.last_selected = -1;
            return;
        }
        if (assignment.last_selected == peer_id) {
            assignment.last_selected = -1;
        }
    };

    for (auto it = m_route_table.begin(); it != m_route_table.end(); ) {
        scrub_assignment(it->second);
        if (it->second.Empty()) {
            it = m_route_table.erase(it);
        } else {
            ++it;
        }
    }
    scrub_assignment(m_local_assignment);
}

// ---------- Activation ----------

bool DandelionManager::IsActive(int current_height) const
{
    return current_height >= Params().GetConsensus().nShieldedMatRiCTDisableHeight;
}

// ---------- Query helpers ----------

size_t DandelionManager::GetStemPoolSize() const
{
    LOCK(m_mutex);
    return m_stempool.size();
}

size_t DandelionManager::GetStemPoolBytes() const
{
    LOCK(m_mutex);
    return m_stempool_bytes;
}

bool DandelionManager::IsInStemMode() const
{
    LOCK(m_mutex);
    return m_stem_mode;
}

std::vector<NodeId> DandelionManager::GetRelayPeers() const
{
    LOCK(m_mutex);
    return m_relay_destinations;
}

} // namespace Dandelion
