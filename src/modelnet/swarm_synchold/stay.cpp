// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_synchold/stay.h>

#include <modelnet/swarm_synchold/codes.h>
#include <modelnet/swarm_synchold/limits.h>

namespace modelnet {

std::string SwarmSyncHoldStay::refusal() const
{
    return std::string{kSwarmSyncHoldHeld};
}

bool SwarmSyncHoldStay::synced() const
{
    return kSwarmSyncHoldSynced;
}

} // namespace modelnet
