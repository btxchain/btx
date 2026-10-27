// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_CAPACT_GRANT_H
#define BITCOIN_MODELNET_SWARM_CAPACT_GRANT_H

#include <modelnet/swarm_capact/grants.h>

#include <string>

namespace modelnet {

/**
 * Grant name.
 * On success the name is stored once and err is cleared.
 * On failure nothing is stored and err is CAPABILITY or REPLAY.
 * A replay leaves the first grant in place. This does not record an
 * action and does not launch a process.
 */
bool SwarmCapActGrantApply(SwarmCapActGrants& grants, const std::string& name, std::string& err);

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_CAPACT_GRANT_H
