// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnomargin.h>

#include <string>

namespace modelnet {

SwarmNotNoMarginResult SwarmNoteNotNoMargin(const SwarmNotNoMargin& note, std::string& err)
{
    SwarmNotNoMarginResult result;
    result.broadcast = false;
    result.applied_blocks = 0;
    // A 160-block close margin is not a broadcast.
    if (note.channel_id.empty()) {
        result.code = "CHANNEL";
        result.broadcast = false;
        result.applied_blocks = 0;
        err = "CHANNEL";
        return result;
    }
    if (note.blocks != 160) {
        result.code = "CAPPED";
        result.broadcast = false;
        result.applied_blocks = 0;
        err = "CAPPED";
        return result;
    }
    if (note.want_broadcast) {
        result.code = "NOT_BROADCAST";
        result.broadcast = false;
        result.applied_blocks = 0;
        err = "NOT_BROADCAST";
        return result;
    }
    result.code = "NOTED";
    result.broadcast = false;
    result.applied_blocks = 0;
    err.clear();
    return result;
}

} // namespace modelnet
