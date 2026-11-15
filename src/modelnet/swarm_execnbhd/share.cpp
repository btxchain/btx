// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_execnbhd/share.h>

#include <modelnet/swarm_execnbhd/codes.h>

#include <string>

namespace modelnet {

bool SwarmExecNbhdShareKv(const SwarmExecNbhdSeating& seating, const std::string& left_peer,
                          const std::string& right_peer, std::string& err)
{
    if (!seating.seated(left_peer) || !seating.seated(right_peer)) {
        return SwarmExecNbhdRefuse(err, SWARM_EXECNBHD_NOT_SEATED);
    }
    if (seating.domain(left_peer) != seating.domain(right_peer)) {
        return SwarmExecNbhdRefuse(err, SWARM_EXECNBHD_NOT_COMPAT);
    }
    return SwarmExecNbhdAccept(err);
}

} // namespace modelnet
