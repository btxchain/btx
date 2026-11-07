// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnoxferred.h>

#include <string>

namespace modelnet {

SwarmNotNoXferredResult SwarmNoteNotNoXferred(const SwarmNotNoXferred& note, std::string& err)
{
    SwarmNotNoXferredResult result;
    result.published = false;
    result.bytes = 0;
    if (note.run_id.empty()) {
        result.code = "RUN";
        result.published = false;
        result.bytes = 0;
        err = "RUN";
        return result;
    }
    // A unit note publishes no transferred-byte count.
    if (note.want_publish) {
        result.code = "UNMEASURED";
        result.published = false;
        result.bytes = 0;
        err = "UNMEASURED";
        return result;
    }
    result.code = "NOTED";
    result.published = false;
    result.bytes = 0;
    err.clear();
    return result;
}

} // namespace modelnet
