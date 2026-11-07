// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_nodedefault/spend.h>

#include <modelnet/swarm_nodedefault/codes.h>

#include <string>

namespace modelnet {

bool SwarmNodeDefaultSpend::ArmSpend(int64_t atoms, bool operator_signed, bool research_key, bool scheduler, std::string& err)
{
    if (m_armed) {
        err = kSwarmNodeDefaultReplay;
        return false;
    }
    if (!m_sign.Accept(operator_signed, research_key, scheduler, err)) {
        return false;
    }
    if (!m_bound.Accept(atoms, err)) {
        return false;
    }
    m_automatic_spend = std::to_string(atoms);
    m_armed = true;
    err.clear();
    return true;
}

const std::string& SwarmNodeDefaultSpend::automatic_spend() const
{
    return m_automatic_spend;
}

bool SwarmNodeDefaultSpend::armed() const
{
    return m_armed;
}

int64_t SwarmNodeDefaultSpend::atoms_moved() const
{
    return kSwarmNodeDefaultAtomsMoved;
}

} // namespace modelnet
