// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_faultboard/result.h>

#include <modelnet/swarm_faultboard/codes.h>

#include <string>

namespace modelnet {

bool SwarmFaultResultBook::Keep(const std::string& task, const std::string& receipt, std::string& err)
{
    const auto found = m_rows.find(task);
    if (found != m_rows.end()) {
        if (found->second == receipt) {
            err.clear();
            return true;
        }
        err = kSwarmFaultConflict;
        return false;
    }
    m_rows.emplace(task, receipt);
    err.clear();
    return true;
}

bool SwarmFaultResultBook::contains(const std::string& task) const
{
    return m_rows.find(task) != m_rows.end();
}

std::string SwarmFaultResultBook::receipt_for(const std::string& task) const
{
    const auto found = m_rows.find(task);
    if (found == m_rows.end()) {
        return {};
    }
    return found->second;
}

} // namespace modelnet
