// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_idledrain/cap.h>

#include <modelnet/swarm_idledrain/codes.h>
#include <modelnet/swarm_idledrain/limits.h>

namespace modelnet {

bool SwarmIdleDrainCap::accept(int64_t workers, std::string& err) const
{
    // 64 is still inside the cap. One more worker would pass it.
    if (workers >= kSwarmIdleDrainWorkerCap) {
        err = kSwarmIdleDrainCapped;
        return false;
    }
    return true;
}

} // namespace modelnet
