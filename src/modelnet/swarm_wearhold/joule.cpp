// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_wearhold/joule.h>

#include <modelnet/swarm_wearhold/limits.h>

namespace modelnet {

bool SwarmWearHoldBelowOne(int64_t joules)
{
    return joules < kSwarmWearHoldMinJoule;
}

bool SwarmWearHoldStorable(int64_t joules)
{
    return !SwarmWearHoldBelowOne(joules);
}

} // namespace modelnet
