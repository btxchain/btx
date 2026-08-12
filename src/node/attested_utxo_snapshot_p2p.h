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
#include <ios>
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

    template <typename Stream>
    void Serialize(Stream& s) const
    {
        s << block_hash << chunk_index << chunk_hash;
        WriteCompactSize(s, data.size());
        if (!data.empty()) s.write(MakeByteSpan(data));
    }

    template <typename Stream>
    void Unserialize(Stream& s)
    {
        s >> block_hash >> chunk_index >> chunk_hash;
        const uint64_t size{ReadCompactSize(s)};
        if (size > ATTESTED_UTXO_SNAPSHOT_MAX_CHUNK_SIZE) {
            throw std::ios_base::failure(
                "attested UTXO snapshot chunk exceeds policy limit");
        }
        data.resize(static_cast<size_t>(size));
        if (!data.empty()) s.read(MakeWritableByteSpan(data));
    }
};

/**
 * Process-local coordinator for RPC-driven attested snapshot fetches and for
 * server-side DoS accounting. Message delivery is fulfilled from net_processing.
 */
class AttestedUTXOSnapshotP2P
{
public:
    using SessionId = uint64_t;
    static constexpr size_t MAX_CLIENT_SESSIONS{4};
    static AttestedUTXOSnapshotP2P& Get();

    void ResetForTest();

    /** Server: admit a manifest request under rate limits. */
    [[nodiscard]] bool AdmitManifestRequest(NodeId peer, std::chrono::microseconds now);
    /** Server: admit a chunk request under rate / concurrency limits. */
    [[nodiscard]] bool AdmitChunkRequest(NodeId peer, std::chrono::microseconds now);
    void ReleaseChunkTransfer(NodeId peer);
    void PeerDisconnected(NodeId peer);

    /**
     * Client: allocate an isolated fetch session. Concurrent RPCs cannot
     * cancel, overwrite, or consume each other's replies.
     */
    [[nodiscard]] std::optional<SessionId> BeginSession(
        NodeId peer, const uint256& block_hash);
    [[nodiscard]] bool BeginChunkWait(SessionId session, uint32_t chunk_index);
    void CancelSession(SessionId session);

    void DeliverManifest(NodeId peer, AttestedUTXOSnapshotManifestMsg msg);
    void DeliverChunk(NodeId peer, AttestedUTXOSnapshotChunkMsg msg);

    [[nodiscard]] std::optional<AttestedUTXOSnapshotManifestMsg> WaitManifest(
        SessionId session, std::chrono::milliseconds timeout);
    [[nodiscard]] std::optional<AttestedUTXOSnapshotChunkMsg> WaitChunk(
        SessionId session, std::chrono::milliseconds timeout);

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

    struct ClientSession {
        NodeId peer{-1};
        uint256 block_hash{};
        bool waiting_manifest{true};
        bool waiting_chunk{false};
        bool cancelled{false};
        uint32_t chunk_index{0};
        std::optional<AttestedUTXOSnapshotManifestMsg> manifest{};
        std::optional<AttestedUTXOSnapshotChunkMsg> chunk{};
    };
    std::map<SessionId, ClientSession> m_sessions GUARDED_BY(m_mutex);
    SessionId m_next_session GUARDED_BY(m_mutex){1};
};

} // namespace node

#endif // BTX_NODE_ATTESTED_UTXO_SNAPSHOT_P2P_H
