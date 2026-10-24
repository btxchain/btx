// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notttft.h>

#include <string>

namespace modelnet {

SwarmNotTtftResult SwarmNoteNotTtft(const SwarmNotTtft& note, std::string& err)
{
    SwarmNotTtftResult result;
    result.published = false;
    // No time-to-first-token has been measured, so this note does not publish one.
    if (note.node_id.empty()) {
        result.code = "TTFT";
        result.published = false;
        err = "TTFT";
        return result;
    }
    if (note.want_publish) {
        result.code = "UNMEASURED";
        result.published = false;
        err = "UNMEASURED";
        return result;
    }
    result.code = "NOTED";
    result.published = false;
    err.clear();
    return result;
}

} // namespace modelnet
