// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_WATCHHOLD_RELEASE_H
#define BITCOIN_MODELNET_SWARM_WATCHHOLD_RELEASE_H

#include <string>

namespace modelnet {

/**
 * Refuse to release a secret.
 * The result is always HELD. No secret bytes are accepted or stored.
 * There is no broadcast.
 */
bool SwarmWatchHoldRelease(std::string& err);

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_WATCHHOLD_RELEASE_H
