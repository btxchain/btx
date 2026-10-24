// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnop50pub2.h>

#include <string>

namespace modelnet {

SwarmNotNoP50Pub2Result SwarmNoteNotNoP50Pub2(const SwarmNotNoP50Pub2& note, std::string& err)
{
    SwarmNotNoP50Pub2Result result;
    result.published = false;
    if (note.sample_id.empty()) {
        result.code = "SAMPLE";
        result.published = false;
        err = "SAMPLE";
        return result;
    }
    // This note publishes no p50 latency.
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
