// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_watchhold/silence.h>

#include <modelnet/swarm_watchhold/limits.h>

namespace modelnet {

bool SwarmWatchHoldSilence::broadcast() const
{
    return kSwarmWatchHoldBroadcast;
}

bool SwarmWatchHoldSilence::mined() const
{
    return kSwarmWatchHoldMined;
}

int64_t SwarmWatchHoldSilence::bytes_moved() const
{
    return kSwarmWatchHoldBytesMoved;
}

} // namespace modelnet
