// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_minehold/stay.h>

#include <modelnet/swarm_minehold/codes.h>
#include <modelnet/swarm_minehold/limits.h>

namespace modelnet {

std::string SwarmMineHoldStay::refusal() const
{
    return std::string{kSwarmMineHoldHeld};
}

bool SwarmMineHoldStay::mined() const
{
    return kSwarmMineHoldMined;
}

int64_t SwarmMineHoldStay::blocks() const
{
    return kSwarmMineHoldBlocks;
}

} // namespace modelnet
