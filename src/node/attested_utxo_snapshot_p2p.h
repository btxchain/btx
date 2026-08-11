// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_NODE_ATTESTED_UTXO_SNAPSHOT_P2P_H
#define BTX_NODE_ATTESTED_UTXO_SNAPSHOT_P2P_H

#include <matmul/trusted_utxo_snapshot_attestation.h>
#include <node/attested_utxo_snapshot.h>
#include <net.h>
#include <serialize.h>
#include <sync.h>
#include <uint256.h>

#include <chrono>
#include <condition_variable>
#include <cstdint>
#include <map>
#include <mutex>
#include <optional>
#include <string>
#include <vector>

class CNode;
class CConnman;

namespace node {

/** Wire header for utxomanifest (manifest follows as nested serialize). */
struct AttestedUTXOSnapshotManifestMsg {
    uint256 block_hash{};
    int32_t height{-1};
    uint64_t file_size{0};
    uint32_t chunk_size{0};
    uint32_t chunk_count{0};
    uint256 file_hash{};
    matmul::trusted::UtxoSnapshotManifest manifest{};

    SERIALIZE_METHODS(AttestedUTXOSnapshotManifestMsg, obj)
    {
        READWRITE(obj.block_hash, obj.height, obj.file_size, obj.chunk_size,
                  obj.chunk_count, obj.file_hash, obj.manifest);
    }
};

struct AttestedUTXOSnapshotChunkMsg {
    uint256 block_hash{};
    uint32_t chunk_index{0};
    uint256 chunk_hash{};
    std::vector<uint8_t> data{};

    SERIALIZE_METHODS(AttestedUTXOSnapshotChunkMsg, obj)
    {
        READWRITE(obj.block_hash, obj.chunk_index, obj.chunk_hash, obj.data);
    }
};

/**
 * Process-local coordinator for RPC-driven attested snapshot fetches and for
 * server-side DoS accounting. Message delivery is fulfilled from net_processing.
 */
class AttestedUTXOSnapshotP2P
{
public:
    static AttestedUTXOSnapshotP2P& Get();

    void ResetForTest();

    /** Server: admit a manifest request under rate limits. */
    [[nodiscard]] bool AdmitManifestRequest(NodeId peer, std::chrono::microseconds now);
    /** Server: admit a chunk request under rate / concurrency limits. */
    [[nodiscard]] bool AdmitChunkRequest(NodeId peer, std::chrono::microseconds now);
    void ReleaseChunkTransfer(NodeId peer);
    void PeerDisconnected(NodeId peer);

    /** Client: register interest so an inbound utxomanifest is delivered here. */
    void BeginManifestWait(NodeId peer, const uint256& block_hash);
    void BeginChunkWait(NodeId peer, const uint256& block_hash, uint32_t chunk_index);
    void CancelWaits();

    void DeliverManifest(NodeId peer, AttestedUTXOSnapshotManifestMsg msg);
    void DeliverChunk(NodeId peer, AttestedUTXOSnapshotChunkMsg msg);

    [[nodiscard]] std::optional<AttestedUTXOSnapshotManifestMsg> WaitManifest(
        std::chrono::milliseconds timeout);
    [[nodiscard]] std::optional<AttestedUTXOSnapshotChunkMsg> WaitChunk(
        std::chrono::milliseconds timeout);

private:
    struct PeerBudget {
        double manifest_tokens{static_cast<double>(ATTESTED_UTXO_SNAPSHOT_MAX_MANIFEST_REQ_PER_MIN)};
        std::chrono::microseconds manifest_refill{0};
        double chunk_tokens{static_cast<double>(ATTESTED_UTXO_SNAPSHOT_MAX_CHUNK_REQ_PER_SEC)};
        std::chrono::microseconds chunk_refill{0};
        size_t active_transfers{0};
    };

    Mutex m_mutex;
    std::condition_variable m_cv;
    std::map<NodeId, PeerBudget> m_budgets GUARDED_BY(m_mutex);
    size_t m_global_transfers GUARDED_BY(m_mutex){0};

    bool m_waiting_manifest GUARDED_BY(m_mutex){false};
    NodeId m_wait_peer GUARDED_BY(m_mutex){-1};
    uint256 m_wait_hash GUARDED_BY(m_mutex){};
    std::optional<AttestedUTXOSnapshotManifestMsg> m_manifest GUARDED_BY(m_mutex);

    bool m_waiting_chunk GUARDED_BY(m_mutex){false};
    uint32_t m_wait_chunk_index GUARDED_BY(m_mutex){0};
    std::optional<AttestedUTXOSnapshotChunkMsg> m_chunk GUARDED_BY(m_mutex);
};

} // namespace node

#endif // BTX_NODE_ATTESTED_UTXO_SNAPSHOT_P2P_H
