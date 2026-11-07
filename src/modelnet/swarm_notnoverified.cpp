// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnoverified.h>

#include <string>

namespace modelnet {

SwarmNotNoVerifiedResult SwarmNoteNotNoVerified(const SwarmNotNoVerified& note, std::string& err)
{
    // Activation happens only from a verified book.
    SwarmNotNoVerifiedResult result;
    result.activated = false;
    result.bytes_moved = false;
    if (note.book_id.empty()) {
        result.code = "BOOK";
        result.activated = false;
        result.bytes_moved = false;
        err = "BOOK";
        return result;
    }
    if (note.unverified) {
        result.code = "NOT_ACTIVE";
        result.activated = false;
        result.bytes_moved = false;
        err = "NOT_ACTIVE";
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
