// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_clockspan/deadline.h>

#include <modelnet/swarm_clockspan/codes.h>

namespace modelnet {

bool SwarmClockSpanDeadline::ClaimDeadline(std::string& err) const
{
    err = kSwarmClockSpanNotDeadline;
    return false;
}

} // namespace modelnet
