// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_CANARYBACK_STAGE_H
#define BITCOIN_MODELNET_SWARM_CANARYBACK_STAGE_H

#include <modelnet/swarm_canaryback/candidate.h>

#include <string>

namespace modelnet {

/**
 * Stores a candidate.
 * An empty id is ID and the candidate stays as it was. A stored id
 * does not change the active id. A new store clears the adopted
 * mark so Adopt can take this id.
 */
class SwarmCanaryBackStage {
public:
    bool Apply(SwarmCanaryBackCandidate& candidate, const std::string& id, std::string& err) const;
};

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_CANARYBACK_STAGE_H
