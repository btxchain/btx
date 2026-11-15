// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_nicheslots/quiet.h>

#include <modelnet/swarm_nicheslots/limits.h>

namespace modelnet {

uint64_t SwarmNicheSlotsQuiet::bytes_moved() const
{
    return kSwarmNicheSlotsBytesMoved;
}

bool SwarmNicheSlotsQuiet::broadcast() const
{
    return kSwarmNicheSlotsBroadcast;
}

} // namespace modelnet
