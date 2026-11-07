// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_nicheslots/names.h>

#include <modelnet/swarm_nicheslots/limits.h>

namespace modelnet {

bool SwarmNicheSlotsKnown(const std::string& niche)
{
    return niche == kSwarmNicheSlotsGeneral || niche == kSwarmNicheSlotsCoding ||
           niche == kSwarmNicheSlotsResearch;
}

} // namespace modelnet
