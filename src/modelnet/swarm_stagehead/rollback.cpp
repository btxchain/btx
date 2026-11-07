// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_stagehead/rollback.h>

#include <modelnet/swarm_stagehead/codes.h>

namespace modelnet {

bool SwarmStageRollback::Restore(SwarmStageActive& active, SwarmStageMemory& memory, std::string& err) const
{
    if (!memory.held()) {
        err = kSwarmStageRollback;
        return false;
    }
    const std::string prior = memory.previous();
    active.assign(prior);
    memory.clear();
    err.clear();
    return true;
}

} // namespace modelnet
