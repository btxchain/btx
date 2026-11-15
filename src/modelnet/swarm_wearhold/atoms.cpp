// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_wearhold/atoms.h>

#include <modelnet/swarm_wearhold/limits.h>

namespace modelnet {

bool SwarmWearHoldAtoms::charged() const
{
    return kSwarmWearHoldCharged;
}

int64_t SwarmWearHoldAtoms::atoms_moved() const
{
    return kSwarmWearHoldAtomsMoved;
}

} // namespace modelnet
