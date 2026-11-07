// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_CAPACT_ACTGATE_H
#define BITCOIN_MODELNET_SWARM_CAPACT_ACTGATE_H

#include <modelnet/swarm_capact/actions.h>
#include <modelnet/swarm_capact/grants.h>

#include <string>

namespace modelnet {

/**
 * Refusal code for an Act that must not record, or empty when the
 * action may be recorded once.
 * An empty name is CAPABILITY. A name that was not granted is NOT_ACTED.
 * A name already recorded is REPLAY. This function does not modify
 * either set.
 */
std::string SwarmCapActActRefusal(const SwarmCapActGrants& grants,
                                   const SwarmCapActActions& actions,
                                   const std::string& name);

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_CAPACT_ACTGATE_H
