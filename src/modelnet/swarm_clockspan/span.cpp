// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_clockspan/span.h>

#include <modelnet/swarm_clockspan/limits.h>

namespace modelnet {

bool SwarmClockSpanBelowOne(int64_t seconds)
{
    return seconds < 1;
}

bool SwarmClockSpanIsExact(int64_t seconds)
{
    return seconds == kSwarmClockSpanSeconds;
}

bool SwarmClockSpanIsOther(int64_t seconds)
{
    if (SwarmClockSpanBelowOne(seconds)) return false;
    return !SwarmClockSpanIsExact(seconds);
}

} // namespace modelnet
