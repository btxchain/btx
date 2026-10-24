// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_COMMUNITY_H
#define BITCOIN_MODELNET_SWARM_COMMUNITY_H

#include <cstdint>
#include <string>

namespace modelnet {

/** Local note of one community pool. Nothing is broadcast. */
struct SwarmCommunity {
    std::string pool_id;
    int64_t other_active{0};
    bool want_stop{false};
};

/**
 * Result of noting a community.
 * stopped stays false: a stop request does not stop the community.
 */
struct SwarmCommunityResult {
    bool continues{false};
    bool stopped{false};
    std::string code;
};

/**
 * Note a community without broadcasting and without stopping it.
 * Order: POOL, then HELD, then ALONE, then NOTED.
 */
SwarmCommunityResult SwarmNoteCommunity(const SwarmCommunity& community, std::string& err);

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_COMMUNITY_H
