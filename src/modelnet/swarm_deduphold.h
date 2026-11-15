// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_DEDUPHOLD_H
#define BITCOIN_MODELNET_SWARM_DEDUPHOLD_H

#include <cstdint>
#include <string>

namespace modelnet {

struct SwarmDedupHold {
    std::string page_id;
    bool cross_realm;
    bool want_move;
};

struct SwarmDedupHoldResult {
    std::string code;
    bool moved;
    int64_t bytes_moved;
};

SwarmDedupHoldResult SwarmHoldDedup(const SwarmDedupHold& page, std::string& err);

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_DEDUPHOLD_H
