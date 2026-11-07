// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_clockspan/range.h>

#include <modelnet/swarm_clockspan/codes.h>
#include <modelnet/swarm_clockspan/span.h>

namespace modelnet {

bool SwarmClockSpanRange::accept(int64_t seconds, std::string& err) const
{
    if (SwarmClockSpanBelowOne(seconds)) {
        err = kSwarmClockSpanRange;
        return false;
    }
    return true;
}

} // namespace modelnet
