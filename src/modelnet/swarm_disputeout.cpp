// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_disputeout.h>

#include <cstdint>
#include <string>

namespace modelnet {

SwarmDisputeOutResult SwarmNoteDisputeOut(const SwarmDisputeOut& dispute, std::string& err)
{
    SwarmDisputeOutResult result;
    result.settled = false;
    result.atoms = 0;
    // A dispute settle request is held and settles no outpoint.
    if (dispute.dispute_id.empty()) {
        result.code = "DISPUTE";
        result.settled = false;
        result.atoms = 0;
        err = "DISPUTE";
        return result;
    }
    if (dispute.want_settle) {
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
