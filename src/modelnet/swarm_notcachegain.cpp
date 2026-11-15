// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notcachegain.h>

#include <string>

namespace modelnet {

SwarmNotCacheGainResult SwarmNoteNotCacheGain(const SwarmNotCacheGain& note, std::string& err)
{
    SwarmNotCacheGainResult result;
    result.published = false;
    if (note.page_id.empty()) {
        result.code = "CACHE";
        result.published = false;
        err = "CACHE";
        return result;
    }
    // No measured cache-reuse improvement against an uncached baseline exists.
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
