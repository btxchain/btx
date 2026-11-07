// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_elechold/atoms.h>

#include <modelnet/swarm_elechold/limits.h>

namespace modelnet {

bool SwarmElecHoldAtoms::charged() const
{
    return kSwarmElecHoldCharged;
}

int64_t SwarmElecHoldAtoms::atoms_moved() const
{
    return kSwarmElecHoldAtomsMoved;
}

} // namespace modelnet
