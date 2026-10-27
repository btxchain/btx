// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_execnbhd/identity.h>

#include <modelnet/swarm_execnbhd/codes.h>

#include <string>

namespace modelnet {

bool SwarmExecNbhdIdentity::Set(const std::string& neighborhood_id, std::string& err)
{
    if (neighborhood_id.empty()) {
        return SwarmExecNbhdRefuse(err, SWARM_EXECNBHD_NEIGHBORHOOD);
    }
    if (!m_id.empty()) {
        if (m_id == neighborhood_id) {
            return SwarmExecNbhdRefuse(err, SWARM_EXECNBHD_REPLAY);
        }
        return SwarmExecNbhdRefuse(err, SWARM_EXECNBHD_HELD);
    }
    m_id = neighborhood_id;
    return SwarmExecNbhdAccept(err);
}

std::string SwarmExecNbhdIdentity::Get() const
{
    return m_id;
}

} // namespace modelnet
