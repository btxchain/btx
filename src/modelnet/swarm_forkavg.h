// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_FORKAVG_H
#define BITCOIN_MODELNET_SWARM_FORKAVG_H

#include <cstdint>
#include <string>

namespace modelnet {

struct SwarmForkAvg {
    std::string branch_id;
    bool compatible;
    bool want_average;
};

struct SwarmForkAvgResult {
    std::string code;
    bool averaged;
    int64_t bytes_moved;
};

SwarmForkAvgResult SwarmNoteForkAverage(const SwarmForkAvg& branch, std::string& err);

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_FORKAVG_H
