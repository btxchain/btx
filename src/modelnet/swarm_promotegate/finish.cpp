// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_promotegate/finish.h>

#include <modelnet/swarm_promotegate/codes.h>

namespace modelnet {

bool SwarmPromoteFinish::Apply(SwarmPromoteActive& active, SwarmPromoteMemory& memory, SwarmPromoteCandidate& slot, SwarmPromoteFlag& flag, std::string& err) const
{
    if (flag.marked()) {
        err = kSwarmPromoteInterrupted;
        return false;
    }
    if (!slot.held()) {
        err = kSwarmPromoteStep;
        return false;
    }
    const std::string staged = slot.id();
    memory.remember(active.id());
    active.assign(staged);
    slot.clear();
    flag.clear();
    err.clear();
    return true;
}

} // namespace modelnet
