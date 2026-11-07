// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_SIGCOVER_NAMES_H
#define BITCOIN_MODELNET_SWARM_SIGCOVER_NAMES_H

#include <string>

namespace modelnet {

/**
 * Empty id is SIGHASH.
 * A present id leaves err unchanged.
 */
bool SwarmSigCoverIdPresent(const std::string& id, std::string& err);

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_SIGCOVER_NAMES_H
