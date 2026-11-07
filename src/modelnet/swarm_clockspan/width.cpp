// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_clockspan/width.h>

#include <modelnet/swarm_clockspan/codes.h>
#include <modelnet/swarm_clockspan/span.h>

namespace modelnet {

bool SwarmClockSpanWidth::accept(int64_t seconds, std::string& err) const
{
    if (SwarmClockSpanIsOther(seconds)) {
        err = kSwarmClockSpanSpacing;
        return false;
    }
    return true;
}

} // namespace modelnet
