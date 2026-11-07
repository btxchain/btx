// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_wearhold/under.h>

#include <modelnet/swarm_wearhold/codes.h>
#include <modelnet/swarm_wearhold/joule.h>

namespace modelnet {

bool SwarmWearHoldUnder::accept(int64_t joules, std::string& err) const
{
    if (SwarmWearHoldBelowOne(joules)) {
        err = kSwarmWearHoldMeasure;
        return false;
    }
    return true;
}

} // namespace modelnet
