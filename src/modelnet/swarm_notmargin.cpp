// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notmargin.h>

#include <string>

namespace modelnet {

SwarmNotMarginResult SwarmNoteNotMargin(const SwarmNotMargin& note, std::string& err)
{
    SwarmNotMarginResult result;
    result.closed = false;
    result.broadcast = false;
    // The close margin is 160 blocks. This note does not close or broadcast.
    if (note.channel_id.empty()) {
        result.code = "CHANNEL";
        result.closed = false;
        result.broadcast = false;
        err = "CHANNEL";
        return result;
    }
    if (note.blocks != 160 || note.want_close) {
        result.code = "HELD";
        result.closed = false;
        result.broadcast = false;
        err = "HELD";
        return result;
    }
    result.code = "NOTED";
    result.closed = false;
    result.broadcast = false;
    err.clear();
    return result;
}

} // namespace modelnet
