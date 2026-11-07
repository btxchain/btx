// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnorevoke2.h>

#include <string>

namespace modelnet {

SwarmNotNoRevoke2Result SwarmNoteNotNoRevoke2(const SwarmNotNoRevoke2& note, std::string& err)
{
    SwarmNotNoRevoke2Result result;
    result.read = false;
    result.bytes_moved = false;
    // A revoked member reads no later cache page.
    if (note.page_id.empty()) {
        result.code = "PAGE";
        result.read = false;
        result.bytes_moved = false;
        err = "PAGE";
        return result;
    }
    if (note.revoked) {
        result.code = "NOT_READ";
        result.read = false;
        result.bytes_moved = false;
        err = "NOT_READ";
        return result;
    }
    if (note.want_read) {
        result.code = "HELD";
        result.read = false;
        result.bytes_moved = false;
        err = "HELD";
        return result;
    }
    result.code = "NOTED";
    result.read = false;
    result.bytes_moved = false;
    err.clear();
    return result;
}

} // namespace modelnet
