// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnop95pub2.h>

#include <string>

namespace modelnet {

SwarmNotNoP95Pub2Result SwarmNoteNotNoP95Pub2(const SwarmNotNoP95Pub2& note, std::string& err)
{
    SwarmNotNoP95Pub2Result result;
    result.published = false;
    if (note.sample_id.empty()) {
        result.code = "SAMPLE";
        result.published = false;
        err = "SAMPLE";
        return result;
    }
    // This note publishes no p95 latency.
    if (note.want_publish) {
        result.code = "HELD";
        result.published = false;
        err = "HELD";
        return result;
    }
    result.code = "NOTED";
    result.published = false;
    err.clear();
    return result;
}

} // namespace modelnet
