// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnoneigh6.h>

namespace modelnet {

SwarmNotNoNeigh6Result SwarmNoteNotNoNeigh6(const SwarmNotNoNeigh6& note, std::string& err)
{
    SwarmNotNoNeigh6Result result;
    result.added = false;
    result.bytes_moved = false;
    // The neighborhood cap is 4 lowest-RTT plus 2 new trust domains. This note adds no peer.
    if (note.peer_id.empty()) {
        result.code = "PEER";
        result.added = false;
        result.bytes_moved = false;
        err = "PEER";
        return result;
    }
    if (note.count > 6) {
        result.code = "NOT_ADDED";
        result.added = false;
        result.bytes_moved = false;
        err = "NOT_ADDED";
        return result;
    }
    if (note.want_add) {
        result.code = "HELD";
        result.added = false;
        result.bytes_moved = false;
        err = "HELD";
        return result;
    }
    result.code = "NOTED";
    result.added = false;
    result.bytes_moved = false;
    err.clear();
    return result;
}

} // namespace modelnet
