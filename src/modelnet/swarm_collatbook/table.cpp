// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_collatbook/table.h>

namespace modelnet {

bool SwarmCollatTable::held(const std::string& outpoint) const
{
    return m_rows.find(outpoint) != m_rows.end();
}

bool SwarmCollatTable::Find(const std::string& outpoint, std::string& pool, std::string& bucket) const
{
    const auto it = m_rows.find(outpoint);
    if (it == m_rows.end()) {
        return false;
    }
    pool = it->second.pool;
    bucket = it->second.bucket;
    return true;
}

bool SwarmCollatTable::Insert(const std::string& pool, const std::string& outpoint, const std::string& bucket)
{
    if (pool.empty() || outpoint.empty() || bucket.empty()) {
        return false;
    }
    if (m_rows.find(outpoint) != m_rows.end()) {
        // The first reservation stays. A second row is not created.
        return false;
    }
    SwarmCollatRow row;
    row.pool = pool;
    row.bucket = bucket;
    m_rows.emplace(outpoint, std::move(row));
    return true;
}

int64_t SwarmCollatTable::rows() const
{
    return static_cast<int64_t>(m_rows.size());
}

} // namespace modelnet
