// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnop502.h>

namespace modelnet {

SwarmNotNoP502Result SwarmNoteNotNoP502(const SwarmNotNoP502& note, std::string& err)
{
    SwarmNotNoP502Result result;
    result.published = false;
    result.p50_us = 0;
    if (note.sample_id.empty()) {
        result.code = "SAMPLE";
        result.published = false;
        result.p50_us = 0;
        err = "SAMPLE";
        return result;
    }
    // A unit note publishes no p50.
    if (note.want_publish) {
        result.code = "UNMEASURED";
        result.published = false;
        result.p50_us = 0;
        err = "UNMEASURED";
        return result;
    }
    result.code = "NOTED";
    result.published = false;
    result.p50_us = 0;
    err.clear();
    return result;
}

} // namespace modelnet
