// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_survivor.h>

namespace modelnet {

bool SwarmDurableLog::Commit(const std::string& coordinator_id, int64_t epoch, const std::string& commitment_id,
                             const std::string& body, std::string& err)
{
    if (coordinator_id.empty() || commitment_id.empty() || body.empty() || epoch < 1) {
        err = "DURABLE";
        return false;
    }
    if (m_epoch > 0 && epoch < m_epoch) {
        err = "STALE";
        return false;
    }
    const auto it = m_rows.find(commitment_id);
    if (it != m_rows.end()) {
        if (it->second.body == body) {
            // Idempotent replay. Do not lower m_epoch and do not rewrite the row.
            err.clear();
            return true;
        }
        err = "CONFLICT";
        return false;
    }
    Record row;
    row.body = body;
    row.epoch = epoch;
    m_rows.emplace(commitment_id, row);
    if (epoch > m_epoch) {
        m_epoch = epoch;
    }
    err.clear();
    return true;
}

bool SwarmDurableLog::Read(const std::string& coordinator_id, int64_t epoch,
                           std::vector<std::string>& commitment_ids, bool& continues, std::string& err) const
{
    if (coordinator_id.empty()) {
        err = "DURABLE";
        continues = false;
        commitment_ids.clear();
        return false;
    }
    if (Count() == 0) {
        err = "EMPTY";
        continues = false;
        commitment_ids.clear();
        return false;
    }
    if (epoch < m_epoch) {
        err = "STALE";
        continues = false;
        commitment_ids.clear();
        return false;
    }
    commitment_ids.clear();
    commitment_ids.reserve(m_rows.size());
    for (const auto& item : m_rows) {
        commitment_ids.push_back(item.first);
    }
    continues = true;
    err.clear();
    return true;
}

int SwarmDurableLog::Count() const
{
    return static_cast<int>(m_rows.size());
}

} // namespace modelnet
