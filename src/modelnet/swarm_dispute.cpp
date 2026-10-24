// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_dispute.h>

namespace modelnet {

bool SwarmDisputeBook::OpenDispute(const std::string& dispute_id, const std::string& receipt_id, std::string& err)
{
    if (dispute_id.empty() || receipt_id.empty()) {
        err = "DISPUTE";
        return false;
    }
    if (m_rows.find(dispute_id) != m_rows.end()) {
        err = "REPLAY";
        return false;
    }
    Row row;
    row.dispute.dispute_id = dispute_id;
    row.dispute.receipt_id = receipt_id;
    row.dispute.state = SwarmDisputeState::Open;
    row.dispute.settled = false;
    row.dispute.broadcast = false;
    row.dispute.outpoint.clear();
    m_rows.emplace(dispute_id, std::move(row));
    err.clear();
    return true;
}

bool SwarmDisputeBook::AddEvidence(const std::string& dispute_id, const std::string& evidence, std::string& err)
{
    const auto it = m_rows.find(dispute_id);
    if (it == m_rows.end()) {
        err = "DISPUTE";
        return false;
    }
    if (evidence.empty()) {
        err = "DISPUTE";
        return false;
    }
    if (it->second.dispute.state == SwarmDisputeState::Open) {
        it->second.evidence = evidence;
        it->second.dispute.state = SwarmDisputeState::Evidence;
        it->second.dispute.settled = false;
        it->second.dispute.broadcast = false;
        it->second.dispute.outpoint.clear();
        err.clear();
        return true;
    }
    if (it->second.dispute.state == SwarmDisputeState::Evidence) {
        err.clear();
        return true;
    }
    err = "REPLAY";
    return false;
}

bool SwarmDisputeBook::Resolve(const std::string& dispute_id, bool accept, std::string& err)
{
    const auto it = m_rows.find(dispute_id);
    if (it == m_rows.end()) {
        err = "DISPUTE";
        return false;
    }
    if (it->second.dispute.state == SwarmDisputeState::Open) {
        err = "EVIDENCE";
        return false;
    }
    if (it->second.dispute.state != SwarmDisputeState::Evidence) {
        err = "REPLAY";
        return false;
    }
    it->second.dispute.state = accept ? SwarmDisputeState::Accepted : SwarmDisputeState::Refused;
    it->second.dispute.settled = false;
    it->second.dispute.broadcast = false;
    it->second.dispute.outpoint.clear();
    err.clear();
    return true;
}

const SwarmDispute* SwarmDisputeBook::Find(const std::string& dispute_id) const
{
    const auto it = m_rows.find(dispute_id);
    if (it == m_rows.end()) {
        return nullptr;
    }
    return &it->second.dispute;
}

} // namespace modelnet
