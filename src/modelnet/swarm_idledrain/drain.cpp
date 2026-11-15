// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_idledrain/drain.h>

#include <modelnet/swarm_idledrain/codes.h>
#include <modelnet/swarm_idledrain/reason.h>
#include <modelnet/swarm_idledrain/replay.h>

namespace modelnet {

bool SwarmIdleDrainDrain::Apply(SwarmIdleDrainMark& mark,
                                 SwarmIdleDrainWorkers& workers,
                                 const std::string& reason,
                                 std::string& err) const
{
    if (!SwarmIdleDrainReason{}.Matches(reason)) {
        err = kSwarmIdleDrainReason;
        return false;
    }
    if (SwarmIdleDrainReplay{}.claimed(mark.set(), err)) {
        return false;
    }
    mark.raise();
    workers.zero();
    err.clear();
    return true;
}

} // namespace modelnet
