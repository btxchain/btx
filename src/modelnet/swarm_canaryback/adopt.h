// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_CANARYBACK_ADOPT_H
#define BITCOIN_MODELNET_SWARM_CANARYBACK_ADOPT_H

#include <modelnet/swarm_canaryback/active.h>
#include <modelnet/swarm_canaryback/candidate.h>
#include <modelnet/swarm_canaryback/prior.h>

#include <string>

namespace modelnet {

/**
 * Makes the staged id active and remembers the previous active id.
 * Nothing staged is STAGE. The same staged id again, with no new
 * Stage, is REPLAY and leaves the active id. The staged id stays
 * after a successful Adopt.
 */
class SwarmCanaryBackAdopt {
public:
    bool Apply(SwarmCanaryBackActive& active, SwarmCanaryBackCandidate& candidate, SwarmCanaryBackPrior& prior, std::string& err) const;
};

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_CANARYBACK_ADOPT_H
