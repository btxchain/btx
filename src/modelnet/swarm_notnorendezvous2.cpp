// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnorendezvous2.h>

#include <string>

namespace modelnet {

SwarmNotNoRendezvous2Result SwarmNoteNotNoRendezvous2(const SwarmNotNoRendezvous2& note, std::string& err)
{
    SwarmNotNoRendezvous2Result result;
    result.opened = false;
    result.bytes_moved = false;
    // A public rendezvous opens no socket.
    if (note.meet_id.empty()) {
        result.code = "MEET";
        result.opened = false;
        result.bytes_moved = false;
        err = "MEET";
        return result;
    }
    if (note.public_meet) {
        result.code = "NOT_OPEN";
        result.opened = false;
        result.bytes_moved = false;
        err = "NOT_OPEN";
        return result;
    }
    if (note.want_open) {
        result.code = "HELD";
        result.opened = false;
        result.bytes_moved = false;
        err = "HELD";
        return result;
    }
    result.code = "NOTED";
    result.opened = false;
    result.bytes_moved = false;
    err.clear();
    return result;
}

} // namespace modelnet
