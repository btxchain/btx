// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnofalsecompat.h>

#include <string>

namespace modelnet {

SwarmNotNoFalseCompatResult SwarmNoteNotNoFalseCompat(const SwarmNotNoFalseCompat& note, std::string& err)
{
    SwarmNotNoFalseCompatResult result;
    result.shared = false;
    result.bytes_moved = false;
    // A false compatibility claim shares no KV page and moves no bytes.
    if (note.page_id.empty()) {
        result.code = "PAGE";
        result.shared = false;
        result.bytes_moved = false;
        err = "PAGE";
        return result;
    }
    if (note.false_compat) {
        result.code = "FAMILY_NOT_COMPAT";
        result.shared = false;
        result.bytes_moved = false;
        err = "FAMILY_NOT_COMPAT";
        return result;
    }
    if (note.want_share) {
        result.code = "NOT_SHARED";
        result.shared = false;
        result.bytes_moved = false;
        err = "NOT_SHARED";
        return result;
    }
    result.code = "NOTED";
    result.shared = false;
    result.bytes_moved = false;
    err.clear();
    return result;
}

} // namespace modelnet
