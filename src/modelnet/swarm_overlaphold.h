// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_OVERLAPHOLD_H
#define BITCOIN_MODELNET_SWARM_OVERLAPHOLD_H

#include <cstdint>
#include <string>

namespace modelnet {

struct SwarmOverlapHold {
    std::string edge_id;
    bool overlapping;
    bool want_claim;
};

struct SwarmOverlapHoldResult {
    std::string code;
    bool claimed;
    int64_t atoms;
};

SwarmOverlapHoldResult SwarmHoldOverlap(const SwarmOverlapHold& edge, std::string& err);

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_OVERLAPHOLD_H
