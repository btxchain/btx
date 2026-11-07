// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_ROUTEBOOK_CLAIM_H
#define BITCOIN_MODELNET_SWARM_ROUTEBOOK_CLAIM_H

#include <string>

namespace modelnet {

/**
 * Refuse a claim. route may be known or unknown. Both are UNQUALIFIED.
 * The route id is not a settlement. No atoms move and nothing is broadcast.
 */
bool SwarmRouteBookRefuseClaim(const std::string& route, std::string& err);

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_ROUTEBOOK_CLAIM_H
