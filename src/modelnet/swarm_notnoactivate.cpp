// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnoactivate.h>

#include <string>

namespace modelnet {

SwarmNotNoActivateResult SwarmNoteNotNoActivate(const SwarmNotNoActivate& note, std::string& err)
{
    // Activation happens only from a verified book and moves no bytes.
    SwarmNotNoActivateResult result;
    result.activated = false;
    result.bytes_moved = false;
    if (note.book_id.empty()) {
        result.code = "BOOK";
        result.activated = false;
        result.bytes_moved = false;
        err = "BOOK";
        return result;
    }
    if (!note.verified) {
        result.code = "NOT_VERIFIED";
        result.activated = false;
        result.bytes_moved = false;
        err = "NOT_VERIFIED";
        return result;
    }
    if (note.want_activate) {
        result.code = "HELD";
        result.activated = false;
        result.bytes_moved = false;
        err = "HELD";
        return result;
    }
    result.code = "NOTED";
    result.activated = false;
    result.bytes_moved = false;
    err.clear();
    return result;
}

} // namespace modelnet
