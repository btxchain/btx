// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnop50.h>

namespace modelnet {

SwarmNotNoP50Result SwarmNoteNotNoP50(const SwarmNotNoP50& note, std::string& err)
{
    SwarmNotNoP50Result result;
    result.published = false;
    result.milliseconds = 0;
    if (note.run_id.empty()) {
        result.code = "RUN";
        result.published = false;
        result.milliseconds = 0;
        err = "RUN";
        return result;
    }
    // A unit note publishes no p50 latency.
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
