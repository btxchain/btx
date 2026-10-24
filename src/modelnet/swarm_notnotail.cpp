// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnotail.h>

namespace modelnet {

SwarmNotNoTailResult SwarmNoteNotNoTail(const SwarmNotNoTail& note, std::string& err)
{
    // A truncated output is not a complete result.
    SwarmNotNoTailResult result;
    result.complete = false;
    result.bytes_moved = false;
    if (note.output_id.empty()) {
        result.code = "OUTPUT";
        result.complete = false;
        result.bytes_moved = false;
        err = "OUTPUT";
        return result;
    }
    if (note.truncated) {
        result.code = "NOT_COMPLETE";
        result.complete = false;
        result.bytes_moved = false;
        err = "NOT_COMPLETE";
        return result;
    }
    if (note.want_complete) {
        result.code = "NOT_COMPLETE";
        result.complete = false;
        result.bytes_moved = false;
        err = "NOT_COMPLETE";
        return result;
    }
    result.code = "NOTED";
    result.complete = false;
    result.bytes_moved = false;
    err.clear();
    return result;
}

} // namespace modelnet
