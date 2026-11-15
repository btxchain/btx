// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_CAPACT_GATE_H
#define BITCOIN_MODELNET_SWARM_CAPACT_GATE_H

#include <modelnet/swarm_capact/grants.h>

#include <string>

namespace modelnet {

/**
 * Refusal code for a Grant that must not store, or empty when the name
 * may be stored.
 * An empty name is CAPABILITY. A name already granted is REPLAY.
 * This function does not modify the grant set.
 */
std::string SwarmCapActGrantRefusal(const SwarmCapActGrants& grants, const std::string& name);

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_CAPACT_GATE_H
