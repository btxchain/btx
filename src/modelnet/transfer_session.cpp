// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/transfer_session.h>

#include <tuple>

namespace modelnet {

CreditBroker::CreditBroker(uint64_t ceiling_bytes) : m_ceiling(ceiling_bytes) {}

bool CreditBroker::TryReserve(uint64_t bytes)
{
    std::lock_guard<std::mutex> lock(m_mu);
    if (bytes == 0) return true;
    // Ceiling 0 is fail-closed (no allocation), not unlimited. Unlimited is an
    // explicit huge ceiling (see GlobalTransferCredits).
    if (m_ceiling == 0) return false;
    if (m_reserved + bytes > m_ceiling) return false;
    m_reserved += bytes;
    return true;
}

void CreditBroker::Release(uint64_t bytes)
{
    std::lock_guard<std::mutex> lock(m_mu);
    if (bytes > m_reserved) m_reserved = 0;
    else m_reserved -= bytes;
}

uint64_t CreditBroker::Reserved() const
{
    std::lock_guard<std::mutex> lock(m_mu);
    return m_reserved;
}

uint64_t CreditBroker::Ceiling() const
{
    std::lock_guard<std::mutex> lock(m_mu);
    return m_ceiling;
}

void CreditBroker::SetCeiling(uint64_t ceiling_bytes)
{
    std::lock_guard<std::mutex> lock(m_mu);
    m_ceiling = ceiling_bytes;
}

CreditBroker& GlobalTransferCredits()
{
    static CreditBroker g{uint64_t{256} * PIECE_SIZE};
    return g;
}

TransferSession::TransferSession(CreditBroker& credit) : m_credit(&credit) {}

uint64_t TransferSession::Generation() const
{
    std::lock_guard<std::mutex> lock(m_mu);
    return m_generation;
}

void TransferSession::Cancel()
{
    std::lock_guard<std::mutex> lock(m_mu);
    ++m_generation;
    for (auto& r : m_ledger) {
        if (r.phase == RequestPhase::COMMITTED || r.phase == RequestPhase::CANCELLED) continue;
        if (r.phase == RequestPhase::CREDIT_RESERVED || r.phase == RequestPhase::SENT ||
            r.phase == RequestPhase::RECEIVING || r.phase == RequestPhase::VERIFYING) {
            m_credit->Release(r.bytes);
        }
        r.phase = RequestPhase::CANCELLED;
        m_outstanding.erase(std::tuple<std::string, uint32_t, uint32_t>{r.endpoint, r.file_index, r.piece_index});
    }
}

bool TransferSession::ReserveAndQueue(const std::string& endpoint, uint32_t file_index, uint32_t piece_index,
                                        uint64_t bytes, uint64_t& request_id, std::string& err)
{
    if (!m_credit->TryReserve(bytes)) {
        err = "credit exhausted";
        return false;
    }
    std::lock_guard<std::mutex> lock(m_mu);
    TransferRequest r;
    r.request_id = m_next_id++;
    r.file_index = file_index;
    r.piece_index = piece_index;
    r.bytes = bytes;
    r.phase = RequestPhase::CREDIT_RESERVED;
    r.endpoint = endpoint;
    r.generation = m_generation;
    m_ledger.push_back(r);
    m_outstanding.insert(std::tuple<std::string, uint32_t, uint32_t>{endpoint, file_index, piece_index});
    request_id = r.request_id;
    return true;
}

void TransferSession::NoteSent(uint64_t request_id)
{
    std::lock_guard<std::mutex> lock(m_mu);
    for (auto& r : m_ledger) {
        if (r.request_id != request_id) continue;
        if (r.generation != m_generation || r.phase == RequestPhase::CANCELLED) return;
        if (r.phase == RequestPhase::CREDIT_RESERVED) r.phase = RequestPhase::SENT;
        m_metrics[r.endpoint].inflight_bytes += r.bytes;
        return;
    }
}

void TransferSession::NoteReceiving(uint64_t request_id)
{
    std::lock_guard<std::mutex> lock(m_mu);
    for (auto& r : m_ledger) {
        if (r.request_id != request_id) continue;
        if (r.generation != m_generation || r.phase == RequestPhase::CANCELLED ||
            r.phase == RequestPhase::COMMITTED || r.phase == RequestPhase::FAILED) {
            return;
        }
        if (r.phase == RequestPhase::CREDIT_RESERVED || r.phase == RequestPhase::SENT) {
            r.phase = RequestPhase::RECEIVING;
        }
        return;
    }
}

void TransferSession::NoteVerifying(uint64_t request_id)
{
    std::lock_guard<std::mutex> lock(m_mu);
    for (auto& r : m_ledger) {
        if (r.request_id != request_id) continue;
        if (r.generation != m_generation || r.phase == RequestPhase::CANCELLED ||
            r.phase == RequestPhase::COMMITTED || r.phase == RequestPhase::FAILED) {
            return;
        }
        if (r.phase == RequestPhase::CREDIT_RESERVED || r.phase == RequestPhase::SENT ||
            r.phase == RequestPhase::RECEIVING) {
            r.phase = RequestPhase::VERIFYING;
        }
        return;
    }
}

void TransferSession::NoteCommitted(uint64_t request_id, uint64_t useful_bytes)
{
    std::lock_guard<std::mutex> lock(m_mu);
    for (auto& r : m_ledger) {
        if (r.request_id != request_id) continue;
        if (r.generation != m_generation || r.phase == RequestPhase::COMMITTED || r.phase == RequestPhase::CANCELLED) return;
        r.phase = RequestPhase::COMMITTED;
        m_credit->Release(r.bytes);
        auto& m = m_metrics[r.endpoint];
        if (m.inflight_bytes >= r.bytes) m.inflight_bytes -= r.bytes;
        else m.inflight_bytes = 0;
        m.completed_pieces += 1;
        m_useful_bytes += useful_bytes;
        m_outstanding.erase(std::tuple<std::string, uint32_t, uint32_t>{r.endpoint, r.file_index, r.piece_index});
        return;
    }
}

void TransferSession::NoteFailed(uint64_t request_id)
{
    std::lock_guard<std::mutex> lock(m_mu);
    for (auto& r : m_ledger) {
        if (r.request_id != request_id) continue;
        if (r.generation != m_generation || r.phase == RequestPhase::COMMITTED ||
            r.phase == RequestPhase::CANCELLED) {
            return;
        }
        r.phase = RequestPhase::FAILED;
        m_credit->Release(r.bytes);
        auto& m = m_metrics[r.endpoint];
        if (m.inflight_bytes >= r.bytes) m.inflight_bytes -= r.bytes;
        else m.inflight_bytes = 0;
        m.timeout_count += 1;
        m_outstanding.erase(std::tuple<std::string, uint32_t, uint32_t>{r.endpoint, r.file_index, r.piece_index});
        return;
    }
}

void TransferSession::ObservePeer(const std::string& endpoint, const PeerMetrics& sample)
{
    std::lock_guard<std::mutex> lock(m_mu);
    auto& m = m_metrics[endpoint];
    if (sample.throughput_bps > 0) m.throughput_bps = sample.throughput_bps;
    m.rtt_ms = sample.rtt_ms;
    m.timeout_count += sample.timeout_count;
    m.invalid_piece_count += sample.invalid_piece_count;
    m.completed_pieces += sample.completed_pieces;
    if (sample.state != PeerXferState::ACTIVE) m.state = sample.state;
    m.state = ClassifyPeer(m);
}

bool TransferSession::GetRequest(uint64_t request_id, TransferRequest& out) const
{
    std::lock_guard<std::mutex> lock(m_mu);
    for (const auto& r : m_ledger) {
        if (r.request_id != request_id) continue;
        out = r;
        return true;
    }
    return false;
}

std::map<std::string, PeerMetrics> TransferSession::Metrics() const
{
    std::lock_guard<std::mutex> lock(m_mu);
    return m_metrics;
}

OutstandingSet TransferSession::Outstanding() const
{
    std::lock_guard<std::mutex> lock(m_mu);
    return m_outstanding;
}

UniValue TransferSession::Json() const
{
    std::lock_guard<std::mutex> lock(m_mu);
    UniValue o(UniValue::VOBJ);
    o.pushKV("generation", static_cast<int64_t>(m_generation));
    o.pushKV("ledger_size", static_cast<int>(m_ledger.size()));
    o.pushKV("outstanding", static_cast<int>(m_outstanding.size()));
    o.pushKV("useful_bytes", static_cast<int64_t>(m_useful_bytes));
    o.pushKV("credit_reserved", static_cast<int64_t>(m_credit->Reserved()));
    o.pushKV("credit_ceiling", static_cast<int64_t>(m_credit->Ceiling()));
    return o;
}

} // namespace modelnet
