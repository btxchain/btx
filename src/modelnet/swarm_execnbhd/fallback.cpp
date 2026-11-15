// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_execnbhd/fallback.h>

#include <modelnet/swarm_execnbhd/codes.h>

#include <string>

namespace modelnet {

bool SwarmExecNbhdFallback(const std::string& peer, std::string& err)
{
    if (peer.empty()) {
        return SwarmExecNbhdRefuse(err, SWARM_EXECNBHD_PEER);
    }
    return SwarmExecNbhdRefuse(err, SWARM_EXECNBHD_NOT_CONNECTED);
}

} // namespace modelnet
