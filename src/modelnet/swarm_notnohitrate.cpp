// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnohitrate.h>

#include <cstdint>
#include <string>

namespace modelnet {

SwarmNotNoHitRateResult SwarmNoteNotNoHitRate(const SwarmNotNoHitRate& note, std::string& err)
{
    SwarmNotNoHitRateResult result;
    result.published = false;
    result.hits = 0;
    // A unit note publishes no cache hit rate.
    if (note.run_id.empty()) {
        result.code = "RUN";
        result.published = false;
        result.hits = 0;
        err = "RUN";
        return result;
    }
    if (note.want_publish) {
        result.code = "UNMEASURED";
        result.published = false;
        result.hits = 0;
        err = "UNMEASURED";
        return result;
    }
    result.code = "NOTED";
    result.published = false;
    result.hits = 0;
    err.clear();
    return result;
}

} // namespace modelnet
