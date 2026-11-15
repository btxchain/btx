// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_clockspan/mine.h>

#include <modelnet/swarm_clockspan/limits.h>

namespace modelnet {

bool SwarmClockSpanMine::mined() const
{
    return kSwarmClockSpanMined;
}

int64_t SwarmClockSpanMine::blocks() const
{
    return kSwarmClockSpanBlocks;
}

} // namespace modelnet
