// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnonat2.h>

#include <string>

namespace modelnet {

SwarmNotNoNat2Result SwarmNoteNotNoNat2(const SwarmNotNoNat2& note, std::string& err)
{
    // NAT traversal publishes no address and moves no bytes.
    SwarmNotNoNat2Result result;
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
        result.code = "NOT_PUBLISHED";
        result.published = false;
        result.bytes_moved = false;
        err = "NOT_PUBLISHED";
        return result;
    }
    result.code = "NOTED";
    result.published = false;
    result.bytes_moved = false;
    err.clear();
    return result;
}

} // namespace modelnet
