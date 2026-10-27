// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnoclose.h>

#include <string>

namespace modelnet {

SwarmNotNoCloseResult SwarmNoteNotNoClose(const SwarmNotNoClose& note, std::string& err)
{
    SwarmNotNoCloseResult result;
    result.broadcast = false;
    result.assumed_bytes = 0;
    // An 8000-byte close size is not a measurement and this note broadcasts nothing.
    if (note.channel_id.empty()) {
        result.code = "CHANNEL";
        result.broadcast = false;
        result.assumed_bytes = 0;
        err = "CHANNEL";
        return result;
    }
    if (note.want_broadcast) {
        result.code = "NOT_BROADCAST";
        result.broadcast = false;
        result.assumed_bytes = 0;
        err = "NOT_BROADCAST";
        return result;
    }
    result.code = "NOTED";
    result.broadcast = false;
    result.assumed_bytes = 0;
    err.clear();
    return result;
}

} // namespace modelnet
