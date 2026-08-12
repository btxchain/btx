// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <node/attested_utxo_snapshot_p2p.h>

#include <logging.h>

#include <algorithm>

namespace node {

AttestedUTXOSnapshotP2P& AttestedUTXOSnapshotP2P::Get()
{
    static AttestedUTXOSnapshotP2P instance;
    return instance;
}

void AttestedUTXOSnapshotP2P::ResetForTest()
{
    LOCK(m_mutex);
    m_budgets.clear();
    m_global_transfers = 0;
    m_sessions.clear();
    m_next_session = 1;
}

bool AttestedUTXOSnapshotP2P::AdmitManifestRequest(NodeId peer,
                                                   std::chrono::microseconds now)
{
    LOCK(m_mutex);
    auto& budget{m_budgets[peer]};
    constexpr auto refill_period{std::chrono::microseconds{60'000'000}};
    if (budget.manifest_refill != 0us) {
        const auto elapsed{now - budget.manifest_refill};
        const double added{
            static_cast<double>(elapsed.count()) /
            static_cast<double>(refill_period.count()) *
            static_cast<double>(ATTESTED_UTXO_SNAPSHOT_MAX_MANIFEST_REQ_PER_MIN)};
        budget.manifest_tokens = std::min(
            static_cast<double>(ATTESTED_UTXO_SNAPSHOT_MAX_MANIFEST_REQ_PER_MIN),
            budget.manifest_tokens + added);
    }
    budget.manifest_refill = now;
    if (budget.manifest_tokens < 1.0) return false;
    budget.manifest_tokens -= 1.0;
    return true;
}

bool AttestedUTXOSnapshotP2P::AdmitChunkRequest(NodeId peer,
                                                std::chrono::microseconds now)
{
    LOCK(m_mutex);
    if (m_global_transfers >= ATTESTED_UTXO_SNAPSHOT_MAX_CONCURRENT_TRANSFERS) {
        return false;
    }
    auto& budget{m_budgets[peer]};
    if (budget.active_transfers >= ATTESTED_UTXO_SNAPSHOT_MAX_TRANSFERS_PER_PEER) {
        return false;
    }
    constexpr auto refill_period{std::chrono::microseconds{1'000'000}};
    if (budget.chunk_refill != 0us) {
        const auto elapsed{now - budget.chunk_refill};
        const double added{
            static_cast<double>(elapsed.count()) /
            static_cast<double>(refill_period.count()) *
            static_cast<double>(ATTESTED_UTXO_SNAPSHOT_MAX_CHUNK_REQ_PER_SEC)};
        budget.chunk_tokens = std::min(
            static_cast<double>(ATTESTED_UTXO_SNAPSHOT_MAX_CHUNK_REQ_PER_SEC),
            budget.chunk_tokens + added);
    }
    budget.chunk_refill = now;
    if (budget.chunk_tokens < 1.0) return false;
    budget.chunk_tokens -= 1.0;
    budget.active_transfers += 1;
    m_global_transfers += 1;
    return true;
}

void AttestedUTXOSnapshotP2P::ReleaseChunkTransfer(NodeId peer)
{
    LOCK(m_mutex);
    auto it{m_budgets.find(peer)};
    if (it == m_budgets.end()) return;
    if (it->second.active_transfers > 0) {
        it->second.active_transfers -= 1;
    }
    if (m_global_transfers > 0) {
        m_global_transfers -= 1;
    }
}

void AttestedUTXOSnapshotP2P::PeerDisconnected(NodeId peer)
{
    LOCK(m_mutex);
    auto it{m_budgets.find(peer)};
    if (it != m_budgets.end()) {
        if (it->second.active_transfers > 0 &&
            m_global_transfers >= it->second.active_transfers) {
            m_global_transfers -= it->second.active_transfers;
        }
        m_budgets.erase(it);
    }
    for (auto& [_, session] : m_sessions) {
        if (session.peer == peer) session.cancelled = true;
    }
    m_cv.notify_all();
}

std::optional<AttestedUTXOSnapshotP2P::SessionId>
AttestedUTXOSnapshotP2P::BeginSession(NodeId peer, const uint256& block_hash)
{
    LOCK(m_mutex);
    if (m_sessions.size() >= MAX_CLIENT_SESSIONS) return std::nullopt;
    const SessionId id{m_next_session++};
    m_sessions.emplace(id, ClientSession{.peer = peer, .block_hash = block_hash});
    return id;
}

bool AttestedUTXOSnapshotP2P::BeginChunkWait(SessionId id, uint32_t chunk_index)
{
    LOCK(m_mutex);
    auto it{m_sessions.find(id)};
    if (it == m_sessions.end() || it->second.cancelled ||
        it->second.waiting_manifest) return false;
    it->second.waiting_chunk = true;
    it->second.chunk_index = chunk_index;
    it->second.chunk.reset();
    return true;
}

void AttestedUTXOSnapshotP2P::CancelSession(SessionId id)
{
    LOCK(m_mutex);
    m_sessions.erase(id);
    m_cv.notify_all();
}

void AttestedUTXOSnapshotP2P::DeliverManifest(NodeId peer,
                                              AttestedUTXOSnapshotManifestMsg msg)
{
    LOCK(m_mutex);
    for (auto& [_, session] : m_sessions) {
        if (!session.waiting_manifest || session.cancelled ||
            session.peer != peer ||
            (!session.block_hash.IsNull() && msg.block_hash != session.block_hash)) {
            continue;
        }
        session.manifest = msg;
        session.block_hash = msg.block_hash;
        session.waiting_manifest = false;
    }
    m_cv.notify_all();
}

void AttestedUTXOSnapshotP2P::DeliverChunk(NodeId peer, AttestedUTXOSnapshotChunkMsg msg)
{
    LOCK(m_mutex);
    for (auto& [_, session] : m_sessions) {
        if (!session.waiting_chunk || session.cancelled ||
            session.peer != peer || msg.block_hash != session.block_hash ||
            msg.chunk_index != session.chunk_index) {
            continue;
        }
        session.chunk = msg;
        session.waiting_chunk = false;
    }
    m_cv.notify_all();
}

std::optional<AttestedUTXOSnapshotManifestMsg> AttestedUTXOSnapshotP2P::WaitManifest(
    SessionId id, std::chrono::milliseconds timeout)
{
    WAIT_LOCK(m_mutex, lock);
    const auto deadline{std::chrono::steady_clock::now() + timeout};
    while (true) {
        auto it{m_sessions.find(id)};
        if (it == m_sessions.end() || it->second.cancelled) return std::nullopt;
        if (it->second.manifest.has_value()) {
            auto out{std::move(it->second.manifest)};
            it->second.manifest.reset();
            return out;
        }
        if (!it->second.waiting_manifest) return std::nullopt;
        if (m_cv.wait_until(lock, deadline) == std::cv_status::timeout) {
            it = m_sessions.find(id);
            if (it != m_sessions.end()) it->second.waiting_manifest = false;
            return std::nullopt;
        }
    }
}

std::optional<AttestedUTXOSnapshotChunkMsg> AttestedUTXOSnapshotP2P::WaitChunk(
    SessionId id, std::chrono::milliseconds timeout)
{
    WAIT_LOCK(m_mutex, lock);
    const auto deadline{std::chrono::steady_clock::now() + timeout};
    while (true) {
        auto it{m_sessions.find(id)};
        if (it == m_sessions.end() || it->second.cancelled) return std::nullopt;
        if (it->second.chunk.has_value()) {
            auto out{std::move(it->second.chunk)};
            it->second.chunk.reset();
            return out;
        }
        if (!it->second.waiting_chunk) return std::nullopt;
        if (m_cv.wait_until(lock, deadline) == std::cv_status::timeout) {
            it = m_sessions.find(id);
            if (it != m_sessions.end()) it->second.waiting_chunk = false;
            return std::nullopt;
        }
    }
}

} // namespace node
