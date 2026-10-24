// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnooutpoint.h>

#include <cstdint>
#include <string>

namespace modelnet {

SwarmNotNoOutpointResult SwarmNoteNotNoOutpoint(const SwarmNotNoOutpoint& note, std::string& err)
{
    SwarmNotNoOutpointResult result;
    result.settled = false;
    result.atoms = 0;
    // A dispute note settles no outpoint and pays nothing.
    if (note.dispute_id.empty()) {
        result.code = "DISPUTE";
        result.settled = false;
        result.atoms = 0;
        err = "DISPUTE";
        return result;
    }
    if (note.want_settle) {
        result.code = "NOT_SETTLED";
        result.settled = false;
        result.atoms = 0;
        err = "NOT_SETTLED";
        return result;
    }
    result.code = "NOTED";
    result.settled = false;
    result.atoms = 0;
    err.clear();
    return result;
}

} // namespace modelnet
