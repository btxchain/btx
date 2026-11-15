// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_cachestand.h>

namespace modelnet {

SwarmCacheStandResult SwarmNoteCacheAlone(const SwarmCacheStand& cache, std::string& err)
{
    // A cache that stands alone is not shared.
    SwarmCacheStandResult result;
    result.shared = false;
    result.bytes_moved = 0;
    if (cache.cache_id.empty()) {
        result.code = "CACHE";
        result.shared = false;
        result.bytes_moved = 0;
        err = "CACHE";
        return result;
    }
    if (cache.alone) {
        result.code = "ALONE";
        result.shared = false;
        result.bytes_moved = 0;
        err = "ALONE";
        return result;
    }
    if (cache.want_share) {
        result.code = "HELD";
        result.shared = false;
        result.bytes_moved = 0;
        err = "HELD";
        return result;
    }
    result.code = "NOTED";
    result.shared = false;
    result.bytes_moved = 0;
    err.clear();
    return result;
}

} // namespace modelnet
