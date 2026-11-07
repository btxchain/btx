// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnoassumed.h>

#include <cstdint>
#include <string>

namespace modelnet {

SwarmNotNoAssumedResult SwarmNoteNotNoAssumed(const SwarmNotNoAssumed& note, std::string& err)
{
    SwarmNotNoAssumedResult result;
    result.published = false;
    result.exits = 0;
    // An assumed mass-exit size is not a measurement.
    if (note.run_id.empty()) {
        result.code = "RUN";
        result.published = false;
        result.exits = 0;
        err = "RUN";
        return result;
    }
    if (note.assumed) {
        result.code = "UNMEASURED";
        result.published = false;
        result.exits = 0;
        err = "UNMEASURED";
        return result;
    }
    if (note.want_publish) {
        result.code = "HELD";
        result.published = false;
        result.exits = 0;
        err = "HELD";
        return result;
    }
    result.code = "NOTED";
    result.published = false;
    result.exits = 0;
    err.clear();
    return result;
}

} // namespace modelnet
