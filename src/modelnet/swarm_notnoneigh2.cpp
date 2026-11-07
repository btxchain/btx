// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnoneigh2.h>

#include <string>

namespace modelnet {

SwarmNotNoNeigh2Result SwarmNoteNotNoNeigh2(const SwarmNotNoNeigh2& note, std::string& err)
{
    SwarmNotNoNeigh2Result result;
    result.connected = false;
    result.bytes_moved = false;
    if (note.peer_id.empty()) {
        result.code = "PEER";
        result.connected = false;
        result.bytes_moved = false;
        err = "PEER";
        return result;
    }
    // A neighborhood of four lowest-RTT peers plus two new trust domains does not connect a peer outside that set.
    if (note.outside_set) {
        result.code = "NOT_CONNECTED";
        result.connected = false;
        result.bytes_moved = false;
        err = "NOT_CONNECTED";
        return result;
    }
    if (note.want_connect) {
        result.code = "HELD";
        result.connected = false;
        result.bytes_moved = false;
        err = "HELD";
        return result;
    }
    result.code = "NOTED";
    result.connected = false;
    result.bytes_moved = false;
    err.clear();
    return result;
}

} // namespace modelnet
