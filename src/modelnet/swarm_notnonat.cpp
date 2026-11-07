// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnonat.h>

#include <string>

namespace modelnet {

SwarmNotNoNatResult SwarmNoteNotNoNat(const SwarmNotNoNat& note, std::string& err)
{
    // NAT traversal publishes no address and moves no bytes.
    SwarmNotNoNatResult result;
    result.published = false;
    result.bytes_moved = false;
    if (note.peer_id.empty()) {
        result.code = "PEER";
        result.published = false;
        result.bytes_moved = false;
        err = "PEER";
        return result;
    }
    if (note.want_publish) {
        result.code = "NO_ADDR";
        result.published = false;
        result.bytes_moved = false;
        err = "NO_ADDR";
        return result;
    }
    result.code = "NOTED";
    result.published = false;
    result.bytes_moved = false;
    err.clear();
    return result;
}

} // namespace modelnet
