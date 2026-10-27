// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnobody.h>

namespace modelnet {

SwarmNotNoBodyResult SwarmNoteNotNoBody(const SwarmNotNoBody& note, std::string& err)
{
    // The body cap is 32 MiB and this note stores nothing.
    SwarmNotNoBodyResult result;
    result.stored = false;
    result.applied_bytes = 0;
    if (note.body_id.empty()) {
        result.code = "BODY";
        result.stored = false;
        result.applied_bytes = 0;
        err = "BODY";
        return result;
    }
    if (note.size_bytes != 33554432) {
        result.code = "CAPPED";
        result.stored = false;
        result.applied_bytes = 0;
        err = "CAPPED";
        return result;
    }
    if (note.want_store) {
        result.code = "CAPPED";
        result.stored = false;
        result.applied_bytes = 0;
        err = "CAPPED";
        return result;
    }
    result.code = "NOTED";
    result.stored = false;
    result.applied_bytes = 0;
    err.clear();
    return result;
}

} // namespace modelnet
