// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notfalsecompat.h>

#include <string>

namespace modelnet {

SwarmNotFalseCompatResult SwarmNoteNotFalseCompat(const SwarmNotFalseCompat& note, std::string& err)
{
    SwarmNotFalseCompatResult result;
    result.shared = false;
    result.bytes_moved = false;
    // A discovery peer advertising false compatibility has not been shown as a live share.
    if (note.peer_id.empty()) {
        result.code = "PEER";
        result.shared = false;
        result.bytes_moved = false;
        err = "PEER";
        return result;
    }
    if (note.want_share) {
        result.code = "NOT_LIVE";
        result.shared = false;
        result.bytes_moved = false;
        err = "NOT_LIVE";
        return result;
    }
    result.code = "NOTED";
    result.shared = false;
    result.bytes_moved = false;
    err.clear();
    return result;
}

} // namespace modelnet
