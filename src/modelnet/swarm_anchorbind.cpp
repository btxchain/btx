// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_anchorbind.h>

#include <utility>

namespace modelnet {

bool SwarmAnchorBind::Bind(const std::string& checkpoint, const std::string& base, const std::string& digest, std::string& err)
{
    if (checkpoint.empty() || base.empty() || digest.empty()) {
        err = "ANCHOR";
        return false;
    }
    const auto it = m_rows.find(checkpoint);
    if (it != m_rows.end()) {
        if (it->second.base == base && it->second.digest == digest) {
            err.clear();
            return true;
        }
        err = "CONFLICT";
        return false;
    }
    Row row;
    row.base = base;
    row.digest = digest;
    m_rows.emplace(checkpoint, std::move(row));
    err.clear();
    return true;
}

bool SwarmAnchorBind::Bound(const std::string& checkpoint, std::string& base, std::string& digest) const
{
    const auto it = m_rows.find(checkpoint);
    if (it == m_rows.end()) {
        return false;
    }
    base = it->second.base;
    digest = it->second.digest;
    return true;
}

} // namespace modelnet
