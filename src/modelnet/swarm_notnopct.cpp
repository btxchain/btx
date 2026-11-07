// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnopct.h>

namespace modelnet {

SwarmNotNoPctResult SwarmNoteNotNoPct(const SwarmNotNoPct& note, std::string& err)
{
    SwarmNotNoPctResult result;
    result.published = false;
    result.p50 = 0;
    result.p95 = 0;
    if (note.run_id.empty()) {
        result.code = "RUN";
        result.published = false;
        result.p50 = 0;
        result.p95 = 0;
        err = "RUN";
        return result;
    }
    // No latency percentile is published by this note.
    if (note.want_publish) {
        result.code = "UNMEASURED";
        result.published = false;
        result.p50 = 0;
        result.p95 = 0;
        err = "UNMEASURED";
        return result;
    }
    result.code = "NOTED";
    result.published = false;
    result.p50 = 0;
    result.p95 = 0;
    err.clear();
    return result;
}

} // namespace modelnet
