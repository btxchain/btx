// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnoowner.h>

#include <string>

namespace modelnet {

SwarmNotNoOwnerResult SwarmNoteNotNoOwner(const SwarmNotNoOwner& note, std::string& err)
{
    SwarmNotNoOwnerResult result;
    result.moved = false;
    result.broadcast = false;
    // This note moves no owner key.
    if (note.owner_id.empty()) {
        result.code = "OWNER";
        result.moved = false;
        result.broadcast = false;
        err = "OWNER";
        return result;
    }
    if (note.want_move) {
        result.code = "REFUSED";
        result.moved = false;
        result.broadcast = false;
        err = "REFUSED";
        return result;
    }
    result.code = "NOTED";
    result.moved = false;
    result.broadcast = false;
    err.clear();
    return result;
}

} // namespace modelnet
