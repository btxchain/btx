// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_stagehead/adopt.h>

#include <modelnet/swarm_stagehead/codes.h>

namespace modelnet {

bool SwarmStageAdopt::Apply(SwarmStageActive& active, SwarmStageMemory& memory, SwarmStageCandidate& slot, bool local_compatible, std::string& err) const
{
    if (!slot.held()) {
        err = kSwarmStageAdopt;
        return false;
    }
    if (!local_compatible) {
        err = kSwarmStageLocalIncompatible;
        return false;
    }
    const std::string staged = slot.id();
    memory.remember(active.id());
    active.assign(staged);
    slot.clear();
    err.clear();
    return true;
}

} // namespace modelnet
