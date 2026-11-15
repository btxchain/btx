// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnoexit.h>

#include <string>

namespace modelnet {

SwarmNotNoExitResult SwarmNoteNotNoExit(const SwarmNotNoExit& note, std::string& err)
{
    SwarmNotNoExitResult result;
    result.broadcast = false;
    result.confirmed = false;
    // This note broadcasts no exit transaction.
    if (note.channel_id.empty()) {
        result.code = "CHANNEL";
        result.broadcast = false;
        result.confirmed = false;
        err = "CHANNEL";
        return result;
    }
    if (note.want_broadcast) {
        result.code = "NOT_BROADCAST";
        result.broadcast = false;
        result.confirmed = false;
        err = "NOT_BROADCAST";
        return result;
    }
    result.code = "NOTED";
    result.broadcast = false;
    result.confirmed = false;
    err.clear();
    return result;
}

} // namespace modelnet
