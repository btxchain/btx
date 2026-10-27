// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notprefetch.h>

#include <string>

namespace modelnet {

SwarmNotPrefetchResult SwarmNoteNotPrefetch(const SwarmNotPrefetch& note, std::string& err)
{
    SwarmNotPrefetchResult result;
    result.prefetched = false;
    result.bytes_moved = false;
    // Prefetch moves no bytes.
    if (note.page_id.empty()) {
        result.code = "PAGE";
        result.prefetched = false;
        result.bytes_moved = false;
        err = "PAGE";
        return result;
    }
    // Absent engine refuses the note even when the caller did not ask to prefetch.
    if (!note.engine_present) {
        result.code = "ENGINE_ABSENT";
        result.prefetched = false;
        result.bytes_moved = false;
        err = "ENGINE_ABSENT";
        return result;
    }
    // A present engine still prefetches nothing and moves no bytes.
    if (note.want_prefetch) {
        result.code = "HELD";
        result.prefetched = false;
        result.bytes_moved = false;
        err = "HELD";
        return result;
    }
    result.code = "NOTED";
    result.prefetched = false;
    result.bytes_moved = false;
    err.clear();
    return result;
}

} // namespace modelnet
