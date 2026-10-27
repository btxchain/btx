// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnorv2.h>

#include <string>

namespace modelnet {

SwarmNotNoRv2Result SwarmNoteNotNoRv2(const SwarmNotNoRv2& note, std::string& err)
{
    SwarmNotNoRv2Result result;
    result.opened = false;
    result.bytes_moved = false;
    // A public rendezvous opens no socket.
    if (note.rendezvous_id.empty()) {
        result.code = "RV";
        result.opened = false;
        result.bytes_moved = false;
        err = "RV";
        return result;
    }
    if (note.public_rv) {
        result.code = "NOT_OPENED";
        result.opened = false;
        result.bytes_moved = false;
        err = "NOT_OPENED";
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
