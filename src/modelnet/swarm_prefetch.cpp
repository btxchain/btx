// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_prefetch.h>

namespace modelnet {

// A KV prefetch request is held and moves no bytes.
SwarmPrefetchResult SwarmNotePrefetch(const SwarmPrefetchRequest& page, std::string& err)
{
    SwarmPrefetchResult result;
    result.moved = false;
    result.bytes_moved = 0;
    if (page.page_id.empty()) {
        result.code = "PAGE";
        result.moved = false;
        result.bytes_moved = 0;
        err = "PAGE";
        return result;
    }
    if (page.want_prefetch) {
        result.code = "HELD";
        result.moved = false;
        result.bytes_moved = 0;
        err = "HELD";
        return result;
    }
    result.code = "NOTED";
    result.moved = false;
    result.bytes_moved = 0;
    err.clear();
    return result;
}

} // namespace modelnet
