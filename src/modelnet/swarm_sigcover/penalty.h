// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_SIGCOVER_PENALTY_H
#define BITCOIN_MODELNET_SWARM_SIGCOVER_PENALTY_H

#include <string>

namespace modelnet {

/**
 * Refuse a penalty.
 * id may be known or unknown. Both are NOT_PENALTY.
 * Nothing is stored. A penalty is not marked as having happened.
 */
bool SwarmSigCoverRefusePenalty(const std::string& id, std::string& err);

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_SIGCOVER_PENALTY_H
