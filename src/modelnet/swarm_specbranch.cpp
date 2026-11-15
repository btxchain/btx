// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_specbranch.h>

namespace modelnet {

bool SwarmSpeculativeBook::CommitPrimary(const std::string& id, const std::string& digest, std::string& err)
{
    if (id.empty() || digest.empty()) {
        err = "SPECULATIVE";
        return false;
    }
    const auto it = m_rows.find(id);
    if (it != m_rows.end()) {
        if (it->second.primary != digest) {
            err = "REPLAY";
            return false;
        }
        err.clear();
        return true;
    }
    Row row;
    row.primary = digest;
    row.confirmed_speculative = false;
    m_rows.emplace(id, std::move(row));
    err.clear();
    return true;
}

std::string SwarmSpeculativeBook::Speculate(const std::string& id, const std::string& digest, std::string& err)
{
    const auto it = m_rows.find(id);
    if (it == m_rows.end()) {
        err = "SPECULATIVE";
        return "SPECULATIVE";
    }
    if (digest.empty()) {
        err = "SPECULATIVE";
        return "SPECULATIVE";
    }
    Row& row = it->second;
    row.speculative = digest;
    row.confirmed_speculative = (digest == row.primary);
    if (row.confirmed_speculative) {
        err = "MATCH";
        return "MATCH";
    }
    err = "CONFLICT";
    return "CONFLICT";
}

std::string SwarmSpeculativeBook::Committed(const std::string& id) const
{
    const auto it = m_rows.find(id);
    if (it == m_rows.end()) {
        return {};
    }
    return it->second.primary;
}

} // namespace modelnet
