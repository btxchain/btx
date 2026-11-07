// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnohit.h>

namespace modelnet {

SwarmNotNoHitResult SwarmNoteNotNoHit(const SwarmNotNoHit& note, std::string& err)
{
    // No cache-hit rate is published by this note.
    SwarmNotNoHitResult result;
    if (note.cache_id.empty()) {
        result.code = "CACHE";
        result.published = false;
        result.hit_ppm = 0;
        err = "CACHE";
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
