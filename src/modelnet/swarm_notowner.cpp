// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notowner.h>

namespace modelnet {

SwarmNotOwnerResult SwarmNoteNotOwner(const SwarmNotOwner& note, std::string& err)
{
    SwarmNotOwnerResult result;
    result.bytes_moved = false;
    if (note.page_id.empty()) {
        result.code = "PAGE";
        result.bytes_moved = false;
        err = "PAGE";
        return result;
    }
    // A cache owner disappearing during transfer has not been shown.
    if (note.want_transfer) {
        result.code = "NOT_SHOWN";
        result.bytes_moved = false;
        err = "NOT_SHOWN";
        return result;
    }
    result.code = "NOTED";
    result.bytes_moved = false;
    err.clear();
    return result;
}

} // namespace modelnet
