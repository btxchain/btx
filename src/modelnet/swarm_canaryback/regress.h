// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_CANARYBACK_REGRESS_H
#define BITCOIN_MODELNET_SWARM_CANARYBACK_REGRESS_H

#include <modelnet/swarm_canaryback/active.h>
#include <modelnet/swarm_canaryback/candidate.h>
#include <modelnet/swarm_canaryback/prior.h>

#include <string>

namespace modelnet {

/**
 * Restores the previous id once after a successful Adopt.
 * Before any Adopt the result is STAGE and nothing changes.
 * A second Regress with no newer Adopt is ROLLBACK and the active
 * id stays. A successful restore clears the staged id and spends
 * that previous id. It does not walk back further.
 */
class SwarmCanaryBackRegress {
public:
    bool Apply(SwarmCanaryBackActive& active, SwarmCanaryBackCandidate& candidate, SwarmCanaryBackPrior& prior, std::string& err) const;
};

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_CANARYBACK_REGRESS_H
