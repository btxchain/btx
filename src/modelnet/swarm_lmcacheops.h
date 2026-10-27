// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_LMCACHEOPS_H
#define BTX_MODELNET_SWARM_LMCACHEOPS_H

#include <cstdint>
#include <string>

namespace modelnet {

struct SwarmLmcacheOps {
    std::string engine_id;
    bool ops_absent;
    bool want_move;
};

struct SwarmLmcacheOpsResult {
    std::string code;
    bool moved;
    int64_t bytes_moved;
};

SwarmLmcacheOpsResult SwarmNoteLmcacheOps(const SwarmLmcacheOps& engine, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_LMCACHEOPS_H
