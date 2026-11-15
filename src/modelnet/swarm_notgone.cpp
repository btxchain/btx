// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notgone.h>

#include <string>

namespace modelnet {

SwarmNotGoneResult SwarmNoteNotGone(const SwarmNotGone& note, std::string& err)
{
    SwarmNotGoneResult result;
    result.vanished = false;
    // A coordinator disappearing with pending work has not been injected.
    if (note.coord_id.empty()) {
        result.code = "COORD";
        result.vanished = false;
        err = "COORD";
        return result;
    }
    if (note.want_vanish) {
        result.code = "NOT_INJECTED";
        result.vanished = false;
        err = "NOT_INJECTED";
        return result;
    }
    result.code = "NOTED";
    result.vanished = false;
    err.clear();
    return result;
}

} // namespace modelnet
