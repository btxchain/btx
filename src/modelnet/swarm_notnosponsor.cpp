// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnosponsor.h>

#include <string>

namespace modelnet {

SwarmNotNoSponsorResult SwarmNoteNotNoSponsor(const SwarmNotNoSponsor& note, std::string& err)
{
    SwarmNotNoSponsorResult result;
    result.moved = false;
    result.height = 0;
    // An admin cannot move a sponsor refund key or height.
    if (note.refund_id.empty()) {
        result.code = "REFUND";
        result.moved = false;
        result.height = 0;
        err = "REFUND";
        return result;
    }
    if (note.want_move) {
        result.code = "HELD";
        result.moved = false;
        result.height = 0;
        err = "HELD";
        return result;
    }
    result.code = "NOTED";
    result.moved = false;
    result.height = 0;
    err.clear();
    return result;
}

} // namespace modelnet
