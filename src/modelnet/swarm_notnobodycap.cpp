// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnobodycap.h>

#include <string>

namespace modelnet {

SwarmNotNoBodyCapResult SwarmNoteNotNoBodyCap(const SwarmNotNoBodyCap& note, std::string& err)
{
    SwarmNotNoBodyCapResult result;
    result.accepted = false;
    result.bytes_moved = false;
    // A body over 32 MiB is not accepted and moves no bytes.
    if (note.body_id.empty()) {
        result.code = "BODY";
        result.accepted = false;
        result.bytes_moved = false;
        err = "BODY";
        return result;
    }
    if (note.over_cap) {
        result.code = "CAPPED";
        result.accepted = false;
        result.bytes_moved = false;
        err = "CAPPED";
        return result;
    }
    if (note.want_accept) {
        result.code = "CAPPED";
        result.accepted = false;
        result.bytes_moved = false;
        err = "CAPPED";
        return result;
    }
    result.code = "NOTED";
    result.accepted = false;
    result.bytes_moved = false;
    err.clear();
    return result;
}

} // namespace modelnet
