// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_canaryback/adopt.h>

#include <modelnet/swarm_canaryback/codes.h>

namespace modelnet {

bool SwarmCanaryBackAdopt::Apply(SwarmCanaryBackActive& active, SwarmCanaryBackCandidate& candidate, SwarmCanaryBackPrior& prior, std::string& err) const
{
    if (!candidate.held()) {
        err = kSwarmCanaryBackStage;
        return false;
    }
    if (candidate.adopted()) {
        err = kSwarmCanaryBackReplay;
        return false;
    }
    prior.arm(active.get());
    active.replace(candidate.id());
    candidate.mark_adopted();
    err.clear();
    return true;
}

} // namespace modelnet
