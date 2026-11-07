// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnoholdtime.h>

#include <string>

namespace modelnet {

SwarmNotNoHoldTimeResult SwarmNoteNotNoHoldTime(const SwarmNotNoHoldTime& note, std::string& err)
{
    SwarmNotNoHoldTimeResult result;
    result.refunded = false;
    result.claimed = false;
    // A timeout that lets one side refund while the other can still claim is held.
    if (note.dispute_id.empty()) {
        result.code = "DISPUTE";
        result.refunded = false;
        result.claimed = false;
        err = "DISPUTE";
        return result;
    }
    if (note.overlap) {
        result.code = "HELD";
        result.refunded = false;
        result.claimed = false;
        err = "HELD";
        return result;
    }
    if (note.want_refund) {
        result.code = "HELD";
        result.refunded = false;
        result.claimed = false;
        err = "HELD";
        return result;
    }
    result.code = "NOTED";
    result.refunded = false;
    result.claimed = false;
    err.clear();
    return result;
}

} // namespace modelnet
