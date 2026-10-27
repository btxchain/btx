// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_NEIGHBOR_H
#define BITCOIN_MODELNET_SWARM_NEIGHBOR_H

#include <cstdint>
#include <string>

namespace modelnet {

struct SwarmNeighbor {
    std::string node_id;
    int64_t lowest_rtt;
    int64_t new_domains;
    bool want_connect;
};

struct SwarmNeighborResult {
    std::string code;
    bool connected;
    int64_t kept_rtt;
    int64_t kept_domains;
};

SwarmNeighborResult SwarmCapNeighborhood(const SwarmNeighbor& neighbor, std::string& err);

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_NEIGHBOR_H
