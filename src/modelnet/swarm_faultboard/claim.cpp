// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_faultboard/claim.h>

#include <modelnet/swarm_faultboard/codes.h>

#include <string>

namespace modelnet {

bool SwarmFaultClaimBook::Keep(const std::string& task, const std::string& worker, std::string& err)
{
    const auto found = m_rows.find(task);
    if (found != m_rows.end()) {
        if (found->second == worker) {
            err.clear();
            return true;
        }
        err = kSwarmFaultConflict;
        return false;
    }
    m_rows.emplace(task, worker);
    err.clear();
    return true;
}

bool SwarmFaultClaimBook::contains(const std::string& task) const
{
    return m_rows.find(task) != m_rows.end();
}

std::string SwarmFaultClaimBook::worker_for(const std::string& task) const
{
    const auto found = m_rows.find(task);
    if (found == m_rows.end()) {
        return {};
    }
    return found->second;
}

std::size_t SwarmFaultClaimBook::count() const
{
    return m_rows.size();
}

} // namespace modelnet
