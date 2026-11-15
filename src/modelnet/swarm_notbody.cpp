// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notbody.h>

namespace modelnet {

SwarmNotBodyResult SwarmNoteNotBody(const SwarmNotBody& note, std::string& err)
{
    // The body cap is 32 MiB and this note does not store a body.
    SwarmNotBodyResult result;
    result.stored = false;
    result.bytes_moved = false;
    if (note.body_id.empty()) {
        result.code = "BODY";
        result.stored = false;
        result.bytes_moved = false;
        err = "BODY";
        return result;
    }
    if (note.size_bytes > 33554432 || note.want_store) {
        result.code = "CAPPED";
        result.stored = false;
        result.bytes_moved = false;
        err = "CAPPED";
        return result;
    }
    result.code = "NOTED";
    result.stored = false;
    result.bytes_moved = false;
    err.clear();
    return result;
}

} // namespace modelnet
