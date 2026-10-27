// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_clockspan/replay.h>

#include <modelnet/swarm_clockspan/span.h>

namespace modelnet {

bool SwarmClockSpanIsReplay(const SwarmClockSpanBook& book, int64_t seconds)
{
    if (!SwarmClockSpanIsExact(seconds)) return false;
    return book.noted();
}

} // namespace modelnet
