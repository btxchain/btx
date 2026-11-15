// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnetcost.h>

#include <cstdint>
#include <string>

namespace modelnet {

SwarmNotNetCostResult SwarmNoteNotNetCost(const SwarmNotNetCost& note, std::string& err)
{
    SwarmNotNetCostResult result;
    result.published = false;
    result.atoms = 0;
    // This note does not measure network cost or move atoms.
    if (note.peer_id.empty()) {
        result.code = "PEER";
        result.published = false;
        result.atoms = 0;
        err = "PEER";
        return result;
    }
    if (note.want_publish) {
        result.code = "UNMEASURED";
        result.published = false;
        result.atoms = 0;
        err = "UNMEASURED";
        return result;
    }
    result.code = "NOTED";
    result.published = false;
    result.atoms = 0;
    err.clear();
    return result;
}

} // namespace modelnet
