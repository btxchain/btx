// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnottft.h>

namespace modelnet {

SwarmNotNoTtftResult SwarmNoteNotNoTtft(const SwarmNotNoTtft& note, std::string& err)
{
    SwarmNotNoTtftResult result;
    result.published = false;
    result.milliseconds = 0;
    if (note.run_id.empty()) {
        result.code = "RUN";
        result.published = false;
        result.milliseconds = 0;
        err = "RUN";
        return result;
    }
    // No time-to-first-token measurement is published by this note.
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
