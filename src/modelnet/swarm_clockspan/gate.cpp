// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_clockspan/gate.h>

#include <modelnet/swarm_clockspan/codes.h>
#include <modelnet/swarm_clockspan/range.h>
#include <modelnet/swarm_clockspan/replay.h>
#include <modelnet/swarm_clockspan/width.h>

namespace modelnet {

std::string SwarmClockSpanRefusal(const SwarmClockSpanBook& book, int64_t seconds)
{
    std::string err;
    if (!SwarmClockSpanRange{}.accept(seconds, err)) return err;
    if (!SwarmClockSpanWidth{}.accept(seconds, err)) return err;
    if (SwarmClockSpanIsReplay(book, seconds)) return std::string{kSwarmClockSpanReplay};
    return {};
}

} // namespace modelnet
