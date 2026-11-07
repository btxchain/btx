// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notp50.h>

#include <cstdint>
#include <string>

namespace modelnet {

SwarmNotP50Result SwarmNoteNotP50(const SwarmNotP50& note, std::string& err)
{
    SwarmNotP50Result result;
    result.published = false;
    result.latency_us = 0;
    if (note.run_id.empty()) {
        result.code = "LATENCY";
        result.published = false;
        result.latency_us = 0;
        err = "LATENCY";
        return result;
    }
    // No p50 latency has been measured, so this note does not publish one.
    if (note.want_publish) {
        result.code = "UNMEASURED";
        result.published = false;
        result.latency_us = 0;
        err = "UNMEASURED";
        return result;
    }
    result.code = "NOTED";
    result.published = false;
    result.latency_us = 0;
    err.clear();
    return result;
}

} // namespace modelnet
