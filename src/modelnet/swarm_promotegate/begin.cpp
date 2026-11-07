// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_promotegate/begin.h>

#include <modelnet/swarm_promotegate/codes.h>

namespace modelnet {

bool SwarmPromoteBegin::Place(SwarmPromoteCandidate& slot, const std::string& candidate, std::string& err) const
{
    if (candidate.empty() || !slot.replace(candidate)) {
        err = kSwarmPromoteHead;
        return false;
    }
    err.clear();
    return true;
}

} // namespace modelnet
