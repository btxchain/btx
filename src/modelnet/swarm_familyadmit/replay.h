// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_FAMILYADMIT_REPLAY_H
#define BITCOIN_MODELNET_SWARM_FAMILYADMIT_REPLAY_H

#include <modelnet/swarm_familyadmit/roster.h>

#include <string>

namespace modelnet {

/**
 * True when peer is already stored.
 * An empty peer is not a replay. The stored family is not compared and
 * is not replaced.
 */
bool SwarmFamilyAdmitIsReplay(const SwarmFamilyAdmitRoster& roster, const std::string& peer);

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_FAMILYADMIT_REPLAY_H
