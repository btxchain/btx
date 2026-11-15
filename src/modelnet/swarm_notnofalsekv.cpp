// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnofalsekv.h>

#include <string>

namespace modelnet {

SwarmNotNoFalseKvResult SwarmNoteNotNoFalseKv(const SwarmNotNoFalseKv& note, std::string& err)
{
    SwarmNotNoFalseKvResult result;
    result.shared = false;
    result.bytes_moved = false;
    // A false compatibility claim shares no KV page.
    if (note.page_id.empty()) {
        result.code = "PAGE";
        result.shared = false;
        result.bytes_moved = false;
        err = "PAGE";
        return result;
    }
    if (note.false_claim) {
        result.code = "NOT_SHARED";
        result.shared = false;
        result.bytes_moved = false;
        err = "NOT_SHARED";
        return result;
    }
    if (note.want_share) {
        result.code = "HELD";
        result.shared = false;
        result.bytes_moved = false;
        err = "HELD";
        return result;
    }
    result.code = "NOTED";
    result.shared = false;
    result.bytes_moved = false;
    err.clear();
    return result;
}

} // namespace modelnet
