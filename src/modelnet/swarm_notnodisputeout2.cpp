// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnodisputeout2.h>

#include <cstdint>
#include <string>

namespace modelnet {

SwarmNotNoDisputeOut2Result SwarmNoteNotNoDisputeOut2(const SwarmNotNoDisputeOut2& note, std::string& err)
{
    SwarmNotNoDisputeOut2Result result;
    result.settled = false;
    result.atoms = 0;
    // A dispute note settles no outpoint.
    if (note.dispute_id.empty()) {
        result.code = "DISPUTE";
        result.settled = false;
        result.atoms = 0;
        err = "DISPUTE";
        return result;
    }
    if (note.want_settle) {
        result.code = "HELD";
        result.settled = false;
        result.atoms = 0;
        err = "HELD";
        return result;
    }
    result.code = "NOTED";
    result.settled = false;
    result.atoms = 0;
    err.clear();
    return result;
}

} // namespace modelnet
