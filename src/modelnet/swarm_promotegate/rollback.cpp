// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_promotegate/rollback.h>

#include <modelnet/swarm_promotegate/codes.h>

namespace modelnet {

bool SwarmPromoteRollback::Restore(SwarmPromoteActive& active, SwarmPromoteMemory& memory, std::string& err) const
{
    if (!memory.held()) {
        err = kSwarmPromoteRollback;
        return false;
    }
    const std::string prior = memory.previous();
    active.assign(prior);
    memory.clear();
    err.clear();
    return true;
}

} // namespace modelnet
