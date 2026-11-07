// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_clockspan/quiet.h>

#include <modelnet/swarm_clockspan/limits.h>

namespace modelnet {

int64_t SwarmClockSpanQuiet::bytes_moved() const
{
    return kSwarmClockSpanBytesMoved;
}

bool SwarmClockSpanQuiet::broadcast() const
{
    return kSwarmClockSpanBroadcast;
}

} // namespace modelnet
