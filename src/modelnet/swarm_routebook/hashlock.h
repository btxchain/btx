// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_ROUTEBOOK_HASHLOCK_H
#define BITCOIN_MODELNET_SWARM_ROUTEBOOK_HASHLOCK_H

#include <cstdint>
#include <string>

namespace modelnet {

/**
 * Classify a hashlock length against a known route.
 * An unknown route is ROUTE.
 * preimage_len other than 32 is PREIMAGE and claims nothing.
 * preimage_len of 32 is NOT_ROUTE. A digest match is not a settled route.
 * This function stores nothing and always returns false.
 */
bool SwarmRouteBookClassifyHashlock(bool route_known, int64_t preimage_len, std::string& err);

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_ROUTEBOOK_HASHLOCK_H
