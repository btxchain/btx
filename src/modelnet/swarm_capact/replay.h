// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_CAPACT_REPLAY_H
#define BITCOIN_MODELNET_SWARM_CAPACT_REPLAY_H

#include <modelnet/swarm_capact/actions.h>
#include <modelnet/swarm_capact/grants.h>

#include <string>

namespace modelnet {

/**
 * True when name is already granted.
 * An empty name is not a replay. The stored grant is not replaced.
 */
bool SwarmCapActGrantIsReplay(const SwarmCapActGrants& grants, const std::string& name);

/**
 * True when an action for name is already recorded.
 * An empty name is not a replay. The first record is not replaced and
 * a second record is not added.
 */
bool SwarmCapActActionIsReplay(const SwarmCapActActions& actions, const std::string& name);

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_CAPACT_REPLAY_H
