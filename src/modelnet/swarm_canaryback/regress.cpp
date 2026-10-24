// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_canaryback/regress.h>

#include <modelnet/swarm_canaryback/codes.h>

namespace modelnet {

bool SwarmCanaryBackRegress::Apply(SwarmCanaryBackActive& active, SwarmCanaryBackCandidate& candidate, SwarmCanaryBackPrior& prior, std::string& err) const
{
    switch (prior.kind()) {
    case SwarmCanaryBackPriorKind::Unadopted:
        err = kSwarmCanaryBackStage;
        return false;
    case SwarmCanaryBackPriorKind::Spent:
        err = kSwarmCanaryBackRollback;
        return false;
    case SwarmCanaryBackPriorKind::Armed:
        break;
    }
    const std::string previous = prior.id();
    active.replace(previous);
    candidate.clear();
    prior.disarm();
    err.clear();
    return true;
}

} // namespace modelnet
