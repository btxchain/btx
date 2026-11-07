// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnodispute2.h>

#include <string>

namespace modelnet {

SwarmNotNoDispute2Result SwarmNoteNotNoDispute2(const SwarmNotNoDispute2& note, std::string& err)
{
    SwarmNotNoDispute2Result result;
    result.settled = false;
    result.spent = false;
    // A dispute note settles no outpoint.
    if (note.dispute_id.empty()) {
        result.code = "DISPUTE";
        result.settled = false;
        result.spent = false;
        err = "DISPUTE";
        return result;
    }
    if (note.want_settle) {
        result.code = "HELD";
        result.settled = false;
        result.spent = false;
        err = "HELD";
        return result;
    }
    result.code = "NOTED";
    result.settled = false;
    result.spent = false;
    err.clear();
    return result;
}

} // namespace modelnet
