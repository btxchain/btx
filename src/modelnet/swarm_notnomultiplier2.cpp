// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnomultiplier2.h>

namespace modelnet {

// One run publishes no multiplier.
SwarmNotNoMultiplier2Result SwarmNoteNotNoMultiplier2(const SwarmNotNoMultiplier2& note, std::string& err)
{
    SwarmNotNoMultiplier2Result result;
    result.published = false;
    if (note.sample_id.empty()) {
        result.code = "SAMPLE";
        err = "SAMPLE";
        result.published = false;
        return result;
    }
    if (note.want_publish) {
        result.code = "HELD";
        err = "HELD";
        result.published = false;
        return result;
    }
    result.code = "NOTED";
    err.clear();
    result.published = false;
    return result;
}

} // namespace modelnet
