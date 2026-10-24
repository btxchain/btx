// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnohitrate2.h>

#include <string>

namespace modelnet {

SwarmNotNoHitRate2Result SwarmNoteNotNoHitRate2(const SwarmNotNoHitRate2& note, std::string& err)
{
    SwarmNotNoHitRate2Result result;
    result.published = false;
    result.hits = 0;
    // A unit note publishes no cache hit rate.
    if (note.sample_id.empty()) {
        result.code = "SAMPLE";
        result.published = false;
        result.hits = 0;
        err = "SAMPLE";
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
