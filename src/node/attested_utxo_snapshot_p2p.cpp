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
    m_waiting_manifest = false;
    m_waiting_chunk = false;
    m_manifest.reset();
    m_chunk.reset();
    m_wait_peer = -1;
    m_wait_hash.SetNull();
    m_wait_chunk_index = 0;
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
    if (m_wait_peer == peer) {
        m_waiting_manifest = false;
        m_waiting_chunk = false;
        m_cv.notify_all();
    }
}

void AttestedUTXOSnapshotP2P::BeginManifestWait(NodeId peer, const uint256& block_hash)
{
    LOCK(m_mutex);
    m_waiting_manifest = true;
    m_waiting_chunk = false;
    m_wait_peer = peer;
    m_wait_hash = block_hash;
    m_manifest.reset();
    m_chunk.reset();
}

void AttestedUTXOSnapshotP2P::BeginChunkWait(NodeId peer,
                                             const uint256& block_hash,
                                             uint32_t chunk_index)
{
    LOCK(m_mutex);
    m_waiting_chunk = true;
    m_waiting_manifest = false;
    m_wait_peer = peer;
    m_wait_hash = block_hash;
    m_wait_chunk_index = chunk_index;
    m_chunk.reset();
}

void AttestedUTXOSnapshotP2P::CancelWaits()
{
    LOCK(m_mutex);
    m_waiting_manifest = false;
    m_waiting_chunk = false;
    m_wait_peer = -1;
    m_cv.notify_all();
}

void AttestedUTXOSnapshotP2P::DeliverManifest(NodeId peer,
                                              AttestedUTXOSnapshotManifestMsg msg)
{
    LOCK(m_mutex);
    if (!m_waiting_manifest || m_wait_peer != peer) return;
    if (!m_wait_hash.IsNull() && msg.block_hash != m_wait_hash) return;
    m_manifest = std::move(msg);
    m_waiting_manifest = false;
    m_cv.notify_all();
}

void AttestedUTXOSnapshotP2P::DeliverChunk(NodeId peer, AttestedUTXOSnapshotChunkMsg msg)
{
    LOCK(m_mutex);
    if (!m_waiting_chunk || m_wait_peer != peer) return;
    if (msg.block_hash != m_wait_hash || msg.chunk_index != m_wait_chunk_index) return;
    m_chunk = std::move(msg);
    m_waiting_chunk = false;
    m_cv.notify_all();
}

std::optional<AttestedUTXOSnapshotManifestMsg> AttestedUTXOSnapshotP2P::WaitManifest(
    std::chrono::milliseconds timeout)
{
    WAIT_LOCK(m_mutex, lock);
    const auto deadline{std::chrono::steady_clock::now() + timeout};
    while (!m_manifest.has_value() && m_waiting_manifest) {
        if (m_cv.wait_until(lock, deadline) == std::cv_status::timeout) {
            m_waiting_manifest = false;
            return std::nullopt;
        }
    }
    auto out{std::move(m_manifest)};
    m_manifest.reset();
    return out;
}

std::optional<AttestedUTXOSnapshotChunkMsg> AttestedUTXOSnapshotP2P::WaitChunk(
    std::chrono::milliseconds timeout)
{
    WAIT_LOCK(m_mutex, lock);
    const auto deadline{std::chrono::steady_clock::now() + timeout};
    while (!m_chunk.has_value() && m_waiting_chunk) {
        if (m_cv.wait_until(lock, deadline) == std::cv_status::timeout) {
            m_waiting_chunk = false;
            return std::nullopt;
        }
    }
    auto out{std::move(m_chunk)};
    m_chunk.reset();
    return out;
}

} // namespace node
