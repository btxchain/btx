// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_TRANSFER_SESSION_H
#define BITCOIN_MODELNET_TRANSFER_SESSION_H

#include <modelnet/piece_picker.h>
#include <modelnet/types.h>
#include <univalue.h>

#include <cstdint>
#include <map>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

namespace modelnet {

/** Hard credit ceiling shared by all live transfers.
 *  Ceiling 0 is fail-closed (TryReserve of bytes>0 fails); it is not unlimited.
 *  Unlimited requires an explicit huge ceiling (GlobalTransferCredits uses 256*PIECE_SIZE).
 *  Zero available means wait. */
class CreditBroker {
    mutable std::mutex m_mu;
    uint64_t m_ceiling;
    uint64_t m_reserved{0};

public:
    explicit CreditBroker(uint64_t ceiling_bytes);
    bool TryReserve(uint64_t bytes);
    void Release(uint64_t bytes);
    uint64_t Reserved() const;
    uint64_t Ceiling() const;
    void SetCeiling(uint64_t ceiling_bytes);
};

CreditBroker& GlobalTransferCredits();

enum class RequestPhase {
    QUEUED = 0,
    CREDIT_RESERVED = 1,
    SENT = 2,
    RECEIVING = 3,
    VERIFYING = 4,
    COMMITTED = 5,
    CANCELLED = 6,
    FAILED = 7,
};

struct TransferRequest {
    uint64_t request_id{0};
    uint32_t file_index{0};
    uint32_t piece_index{0};
    uint64_t bytes{PIECE_SIZE};
    RequestPhase phase{RequestPhase::QUEUED};
    std::string endpoint;
    uint64_t generation{1};
};

/** Live acquisition state. Only COMMITTED advances unique progress. */
class TransferSession {
    mutable std::mutex m_mu;
    uint64_t m_generation{1};
    uint64_t m_next_id{1};
    CreditBroker* m_credit;
    std::vector<TransferRequest> m_ledger;
    std::map<std::string, PeerMetrics> m_metrics;
    OutstandingSet m_outstanding;
    uint64_t m_useful_bytes{0};

public:
    explicit TransferSession(CreditBroker& credit);
    ~TransferSession() { Cancel(); }
    TransferSession(const TransferSession&) = delete;
    TransferSession& operator=(const TransferSession&) = delete;
    uint64_t Generation() const;
    void Cancel();
    bool ReserveAndQueue(const std::string& endpoint, uint32_t file_index, uint32_t piece_index,
                          uint64_t bytes, uint64_t& request_id, std::string& err);
    void NoteSent(uint64_t request_id);
    void NoteReceiving(uint64_t request_id);
    void NoteVerifying(uint64_t request_id);
    void NoteCommitted(uint64_t request_id, uint64_t useful_bytes);
    void NoteFailed(uint64_t request_id);
    void ObservePeer(const std::string& endpoint, const PeerMetrics& sample);
    bool GetRequest(uint64_t request_id, TransferRequest& out) const;
    std::map<std::string, PeerMetrics> Metrics() const;
    OutstandingSet Outstanding() const;
    UniValue Json() const;
};

struct ThreadJoin {
    std::vector<std::thread> threads;
    ~ThreadJoin() { Join(); }
    void Join()
    {
        for (auto& t : threads) {
            if (t.joinable()) t.join();
        }
    }
};

} // namespace modelnet

#endif // BITCOIN_MODELNET_TRANSFER_SESSION_H
