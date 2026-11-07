// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notp95.h>

#include <string>

namespace modelnet {

SwarmNotP95Result SwarmNoteNotP95(const SwarmNotP95& note, std::string& err)
{
    SwarmNotP95Result result;
    result.published = false;
    if (note.node_id.empty()) {
        result.code = "LATENCY";
        result.published = false;
        err = "LATENCY";
        return result;
    }
    // No p50 or p95 latency has been measured, so this note does not
    // publish one.
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
