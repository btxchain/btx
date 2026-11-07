// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_quota.h>

namespace modelnet {

bool SwarmQuotaBook::Open(int64_t cap_bytes, std::string& err)
{
    if (m_open) {
        err = "REOPEN";
        return false;
    }
    if (cap_bytes <= 0) {
        err = "QUOTA";
        return false;
    }
    m_open = true;
    m_cap = cap_bytes;
    m_rows.clear();
    err.clear();
    return true;
}

bool SwarmQuotaBook::Admit(const std::string& piece_id, int64_t bytes, bool pin, std::string& err)
{
    if (piece_id.empty() || bytes <= 0) {
        err = "PIN";
        return false;
    }
    if (!m_open) {
        err = "NOT_OPEN";
        return false;
    }
    const auto it = m_rows.find(piece_id);
    if (it != m_rows.end()) {
        if (it->second.bytes != bytes) {
            err = "CONFLICT";
            return false;
        }
        if (pin) it->second.pinned = true;
        err.clear();
        return true;
    }
    const int64_t used = Used();
    if (used > m_cap || bytes > m_cap - used) {
        err = "QUOTA";
        return false;
    }
    Row row;
    row.bytes = bytes;
    row.pinned = pin;
    m_rows.emplace(piece_id, row);
    err.clear();
    return true;
}

bool SwarmQuotaBook::Pin(const std::string& piece_id, int64_t bytes, std::string& err)
{
    return Admit(piece_id, bytes, true, err);
}

bool SwarmQuotaBook::Store(const std::string& piece_id, int64_t bytes, std::string& err)
{
    return Admit(piece_id, bytes, false, err);
}

int64_t SwarmQuotaBook::Used() const
{
    int64_t sum = 0;
    for (const auto& item : m_rows) sum += item.second.bytes;
    return sum;
}

int SwarmQuotaBook::Pinned() const
{
    int count = 0;
    for (const auto& item : m_rows) {
        if (item.second.pinned) ++count;
    }
    return count;
}

} // namespace modelnet
