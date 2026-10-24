// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnobody32.h>

namespace modelnet {

SwarmNotNoBody32Result SwarmNoteNotNoBody32(const SwarmNotNoBody32& note, std::string& err)
{
    // The body cap is 32 MiB and this note stores nothing.
    SwarmNotNoBody32Result result;
    result.stored = false;
    result.bytes_moved = false;
    if (note.body_id.empty()) {
        result.code = "BODY";
        result.stored = false;
        result.bytes_moved = false;
        err = "BODY";
        return result;
    }
    if (note.size_bytes != 33554432) {
        result.code = "CAPPED";
        result.stored = false;
        result.bytes_moved = false;
        err = "CAPPED";
        return result;
    }
    if (note.want_store) {
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
