// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_PRIVFAM_REPLAY_H
#define BITCOIN_MODELNET_SWARM_PRIVFAM_REPLAY_H

#include <modelnet/swarm_privfam/roster.h>

#include <string>

namespace modelnet {

/**
 * True when family is already stored.
 * An empty family is not a replay. The stored privacy flag is not
 * compared and is not replaced.
 */
bool SwarmPrivFamIsReplay(const SwarmPrivFamRoster& roster, const std::string& family);

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_PRIVFAM_REPLAY_H
