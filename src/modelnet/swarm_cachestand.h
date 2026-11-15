// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_CACHESTAND_H
#define BTX_MODELNET_SWARM_CACHESTAND_H

#include <cstdint>
#include <string>

namespace modelnet {

struct SwarmCacheStand {
    std::string cache_id;
    bool alone;
    bool want_share;
};

struct SwarmCacheStandResult {
    std::string code;
    bool shared;
    int64_t bytes_moved;
};

SwarmCacheStandResult SwarmNoteCacheAlone(const SwarmCacheStand& cache, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_CACHESTAND_H
