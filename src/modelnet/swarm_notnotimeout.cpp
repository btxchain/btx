// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnotimeout.h>

namespace modelnet {

SwarmNotNoTimeoutResult SwarmNoteNotNoTimeout(const SwarmNotNoTimeout& note, std::string& err)
{
    // A timeout that lets one side refund while the other can still claim
    // is held, and this note refunds nothing.
    SwarmNotNoTimeoutResult result;
    result.refunded = false;
    result.atoms = 0;
    if (note.channel_id.empty()) {
        result.code = "CHANNEL";
        result.refunded = false;
        result.atoms = 0;
        err = "CHANNEL";
        return result;
    }
    // Both paths open is RACE even when want_refund is false.
    if (note.refund_open && note.claim_open) {
        result.code = "RACE";
        result.refunded = false;
        result.atoms = 0;
        err = "RACE";
        return result;
    }
    if (note.want_refund) {
        result.code = "HELD";
        result.refunded = false;
        result.atoms = 0;
        err = "HELD";
        return result;
    }
    result.code = "NOTED";
    result.refunded = false;
    result.atoms = 0;
    err.clear();
    return result;
}

} // namespace modelnet
