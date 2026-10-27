// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_minehold/mine.h>

#include <modelnet/swarm_minehold/limits.h>

namespace modelnet {

bool SwarmMineHoldMine::mined() const
{
    return kSwarmMineHoldMined;
}

int64_t SwarmMineHoldMine::blocks() const
{
    return kSwarmMineHoldBlocks;
}

} // namespace modelnet
