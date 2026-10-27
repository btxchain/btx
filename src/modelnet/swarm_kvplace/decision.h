// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_KVPLACE_DECISION_H
#define BITCOIN_MODELNET_SWARM_KVPLACE_DECISION_H

#include <string>

namespace modelnet {

/**
 * Turn a stored winner into the call result.
 * Transfer without an engine is ENGINE_ABSENT and returns false.
 * Transfer with an engine is LOCAL and returns true.
 * Any other winner returns true and clears err.
 * This does not move bytes and does not mark a benchmark measured.
 */
bool SwarmKvPlaceDecide(const std::string& winner, bool engine_present, std::string& err);

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_KVPLACE_DECISION_H
