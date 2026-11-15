// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_deduphold.h>

namespace modelnet {

// A cross-realm dedup moves nothing.
SwarmDedupHoldResult SwarmHoldDedup(const SwarmDedupHold& page, std::string& err)
{
    SwarmDedupHoldResult out;
    out.moved = false;
    out.bytes_moved = 0;
    if (page.page_id.empty()) {
        out.code = "PAGE";
        err = "PAGE";
        return out;
    }
    if (page.cross_realm) {
        out.code = "CROSS";
        err = "CROSS";
        return out;
    }
    if (page.want_move) {
        out.code = "HELD";
        err = "HELD";
        return out;
    }
    out.code = "NOTED";
    err.clear();
    return out;
}

} // namespace modelnet
