// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_idledrain/admit.h>

#include <modelnet/swarm_idledrain/cap.h>
#include <modelnet/swarm_idledrain/codes.h>

namespace modelnet {

bool SwarmIdleDrainAdmit::Apply(const SwarmIdleDrainMark& mark, SwarmIdleDrainWorkers& workers, std::string& err) const
{
    if (mark.set()) {
        err = kSwarmIdleDrainDrained;
        return false;
    }
    if (!SwarmIdleDrainCap{}.accept(workers.count(), err)) {
        return false;
    }
    workers.increment();
    err.clear();
    return true;
}

} // namespace modelnet
