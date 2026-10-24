// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notlaterpage.h>

#include <string>

namespace modelnet {

SwarmNotLaterPageResult SwarmNoteNotLaterPage(const SwarmNotLaterPage& note, std::string& err)
{
    SwarmNotLaterPageResult result;
    result.read = false;
    result.bytes_moved = false;
    // This note does not read a cache page. read is the bool named read.
    if (note.page_id.empty()) {
        result.code = "PAGE";
        result.read = false;
        result.bytes_moved = false;
        err = "PAGE";
        return result;
    }
    // Revoked refuses the note even when want_read is false.
    if (note.revoked) {
        result.code = "REVOKED";
        result.read = false;
        result.bytes_moved = false;
        err = "REVOKED";
        return result;
    }
    if (note.want_read) {
        result.code = "REVOKED";
        result.read = false;
        result.bytes_moved = false;
        err = "REVOKED";
        return result;
    }
    result.code = "NOTED";
    result.read = false;
    result.bytes_moved = false;
    err.clear();
    return result;
}

} // namespace modelnet
