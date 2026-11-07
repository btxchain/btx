// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnodiloco.h>

#include <string>

namespace modelnet {

SwarmNotNoDilocoResult SwarmNoteNotNoDiloco(const SwarmNotNoDiloco& note, std::string& err)
{
    SwarmNotNoDilocoResult result;
    result.averaged = false;
    result.bytes_moved = false;
    // Island admission does not exchange WAN updates or average weights.
    if (note.island_id.empty()) {
        result.code = "ISLAND";
        result.averaged = false;
        result.bytes_moved = false;
        err = "ISLAND";
        return result;
    }
    if (note.want_average) {
        result.code = "NOT_EXCHANGED";
        result.averaged = false;
        result.bytes_moved = false;
        err = "NOT_EXCHANGED";
        return result;
    }
    result.code = "NOTED";
    result.averaged = false;
    result.bytes_moved = false;
    err.clear();
    return result;
}

} // namespace modelnet
