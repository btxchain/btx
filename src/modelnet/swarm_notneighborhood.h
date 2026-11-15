// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_NOTNEIGHBORHOOD_H
#define BTX_MODELNET_SWARM_NOTNEIGHBORHOOD_H

#include <string>

namespace modelnet {

struct SwarmNotNeighborhood {
    std::string node_id;
    int peer_count{0};
    bool want_connect{false};
};

struct SwarmNotNeighborhoodResult {
    std::string code;
    bool connected{false};
    int chosen{0};
};

// This note does not connect peers. The neighborhood cap is 4 lowest-RTT plus 2 new trust domains, and this note does not select them.
SwarmNotNeighborhoodResult SwarmNoteNotNeighborhood(const SwarmNotNeighborhood& note, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_NOTNEIGHBORHOOD_H
