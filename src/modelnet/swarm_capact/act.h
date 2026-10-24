// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_CAPACT_ACT_H
#define BITCOIN_MODELNET_SWARM_CAPACT_ACT_H

#include <modelnet/swarm_capact/actions.h>
#include <modelnet/swarm_capact/grants.h>

#include <string>

namespace modelnet {

/**
 * Act name only when that capability was granted.
 * On success the action is recorded once and err is cleared. The
 * function returns true.
 * On failure nothing is recorded and err is CAPABILITY, NOT_ACTED, or
 * REPLAY. A replay does not add a second record. This does not launch
 * a process.
 */
bool SwarmCapActApply(const SwarmCapActGrants& grants,
                       SwarmCapActActions& actions,
                       const std::string& name,
                       std::string& err);

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_CAPACT_ACT_H
