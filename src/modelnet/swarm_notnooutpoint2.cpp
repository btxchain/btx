// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnooutpoint2.h>

#include <string>

namespace modelnet {

SwarmNotNoOutpoint2Result SwarmNoteNotNoOutpoint2(const SwarmNotNoOutpoint2& note, std::string& err)
{
    SwarmNotNoOutpoint2Result result;
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
        result.code = "NOT_SETTLED";
        result.settled = false;
        result.spent = false;
        err = "NOT_SETTLED";
        return result;
    }
    result.code = "NOTED";
    result.settled = false;
    result.spent = false;
    err.clear();
    return result;
}

} // namespace modelnet
