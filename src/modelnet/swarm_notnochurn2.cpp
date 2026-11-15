// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnochurn2.h>

#include <string>

namespace modelnet {

SwarmNotNoChurn2Result SwarmNoteNotNoChurn2(const SwarmNotNoChurn2& note, std::string& err)
{
    SwarmNotNoChurn2Result result;
    result.sent = false;
    result.bytes_moved = false;
    // A churned peer sends nothing.
    if (note.peer_id.empty()) {
        result.code = "PEER";
        result.sent = false;
        result.bytes_moved = false;
        err = "PEER";
        return result;
    }
    if (note.churned) {
        result.code = "NOT_SENT";
        result.sent = false;
        result.bytes_moved = false;
        err = "NOT_SENT";
        return result;
    }
    if (note.want_send) {
        result.code = "HELD";
        result.sent = false;
        result.bytes_moved = false;
        err = "HELD";
        return result;
    }
    result.code = "NOTED";
    result.sent = false;
    result.bytes_moved = false;
    err.clear();
    return result;
}

} // namespace modelnet
