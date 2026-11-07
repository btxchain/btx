// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnostay.h>

#include <string>

namespace modelnet {

SwarmNotNoStayResult SwarmNoteNotNoStay(const SwarmNotNoStay& note, std::string& err)
{
    SwarmNotNoStayResult result;
    result.erased = false;
    result.bytes_moved = false;
    // erased and bytes_moved stay false on every path. Previously
    // delivered plaintext stays after revoke.
    if (note.grant_id.empty()) {
        result.code = "GRANT";
        result.erased = false;
        result.bytes_moved = false;
        err = "GRANT";
        return result;
    }
    if (note.revoked) {
        result.code = "STAYS";
        result.erased = false;
        result.bytes_moved = false;
        err = "STAYS";
        return result;
    }
    if (note.want_erase) {
        result.code = "HELD";
        result.erased = false;
        result.bytes_moved = false;
        err = "HELD";
        return result;
    }
    result.code = "NOTED";
    result.erased = false;
    result.bytes_moved = false;
    err.clear();
    return result;
}

} // namespace modelnet
