// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_CAPACT_RECORD_H
#define BITCOIN_MODELNET_SWARM_CAPACT_RECORD_H

#include <string>

namespace modelnet {

/**
 * One granted capability.
 * The name is the id from the successful Grant. A grant does not record
 * an action and does not launch anything.
 */
struct SwarmCapActGrantRecord {
    std::string name;
};

SwarmCapActGrantRecord SwarmCapActMakeGrant(const std::string& name);

/** The name must be non-empty. */
bool SwarmCapActGrantUsable(const SwarmCapActGrantRecord& record);

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_CAPACT_RECORD_H
