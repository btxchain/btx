// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notcachehit.h>

#include <string>

namespace modelnet {

SwarmNotCacheHitResult SwarmNoteNotCacheHit(const SwarmNotCacheHit& note, std::string& err)
{
    SwarmNotCacheHitResult result;
    result.published = false;
    if (note.node_id.empty()) {
        result.code = "HIT";
        result.published = false;
        err = "HIT";
        return result;
    }
    // No cache-hit rate has been measured, so this note does not publish one.
    if (note.want_publish) {
        result.code = "UNMEASURED";
        result.published = false;
        err = "UNMEASURED";
        return result;
    }
    result.code = "NOTED";
    result.published = false;
    err.clear();
    return result;
}

} // namespace modelnet
