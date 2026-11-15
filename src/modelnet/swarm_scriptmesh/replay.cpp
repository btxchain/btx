// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_scriptmesh/replay.h>

namespace modelnet {

namespace {

bool SameHop(const SwarmScriptMeshHop& a, const SwarmScriptMeshHop& b)
{
    return a.claimant == b.claimant && a.hash == b.hash && a.expiry == b.expiry;
}

} // namespace

bool SwarmScriptMeshReplay::Same(const std::vector<SwarmScriptMeshHop>& hops) const
{
    if (!m_armed || m_hops.size() != hops.size()) return false;
    for (std::size_t i = 0; i < hops.size(); ++i) {
        if (!SameHop(m_hops[i], hops[i])) return false;
    }
    return true;
}

void SwarmScriptMeshReplay::Remember(const std::vector<SwarmScriptMeshHop>& hops)
{
    m_hops = hops;
    m_armed = true;
}

void SwarmScriptMeshReplay::Forget()
{
    m_hops.clear();
    m_armed = false;
}

} // namespace modelnet
