// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnooverlap2.h>

namespace modelnet {

SwarmNotNoOverlap2Result SwarmNoteNotNoOverlap2(const SwarmNotNoOverlap2& note, std::string& err)
{
    // An overlapping timeout is held, and this note refunds nothing
    // and claims nothing.
    SwarmNotNoOverlap2Result result;
    result.refunded = false;
    result.claimed = false;
    if (note.timeout_id.empty()) {
        result.code = "TIMEOUT";
        result.refunded = false;
        result.claimed = false;
        err = "TIMEOUT";
        return result;
    }
    // Overlapping is HELD even when want_refund is false.
    if (note.overlapping) {
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
