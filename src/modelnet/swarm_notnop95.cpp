// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnop95.h>

namespace modelnet {

SwarmNotNoP95Result SwarmNoteNotNoP95(const SwarmNotNoP95& note, std::string& err)
{
    SwarmNotNoP95Result result;
    result.published = false;
    result.milliseconds = 0;
    if (note.run_id.empty()) {
        result.code = "RUN";
        result.published = false;
        result.milliseconds = 0;
        err = "RUN";
        return result;
    }
    // A unit note publishes no p95 latency.
    if (note.want_publish) {
        result.code = "UNMEASURED";
        result.published = false;
        result.milliseconds = 0;
        err = "UNMEASURED";
        return result;
    }
    result.code = "NOTED";
    result.published = false;
    result.milliseconds = 0;
    err.clear();
    return result;
}

} // namespace modelnet
