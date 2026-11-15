// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnocache.h>

#include <cstdint>
#include <string>

namespace modelnet {

SwarmNotNoCacheResult SwarmNoteNotNoCache(const SwarmNotNoCache& note, std::string& err)
{
    SwarmNotNoCacheResult result;
    result.published = false;
    result.hit_ppm = 0;
    // Cache off publishes no hit rate.
    if (note.cache_id.empty()) {
        result.code = "CACHE";
        result.published = false;
        result.hit_ppm = 0;
        err = "CACHE";
        return result;
    }
    if (!note.cache_on) {
        result.code = "UNMEASURED";
        result.published = false;
        result.hit_ppm = 0;
        err = "UNMEASURED";
        return result;
    }
    if (note.want_publish) {
        result.code = "UNMEASURED";
        result.published = false;
        result.hit_ppm = 0;
        err = "UNMEASURED";
        return result;
    }
    result.code = "NOTED";
    result.published = false;
    result.hit_ppm = 0;
    err.clear();
    return result;
}

} // namespace modelnet
