// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_rollback.h>

namespace modelnet {

bool SwarmRollback::Stage(const std::string& candidate, std::string& err)
{
    if (candidate.empty()) {
        err = "MODEL";
        return false;
    }
    m_staged = candidate;
    err.clear();
    return true;
}

bool SwarmRollback::Adopt(std::string& err)
{
    if (m_staged.empty()) {
        err = "STAGE";
        return false;
    }
    m_previous = m_active;
    m_has_previous = true;
    m_active = m_staged;
    m_staged.clear();
    err.clear();
    return true;
}

bool SwarmRollback::Rollback(std::string& err)
{
    if (!m_has_previous) {
        err = "ROLLBACK";
        return false;
    }
    m_active = m_previous;
    m_previous.clear();
    m_has_previous = false;
    err.clear();
    return true;
}

const std::string& SwarmRollback::active() const
{
    return m_active;
}

} // namespace modelnet
