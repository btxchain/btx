// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_overlaphold.h>

namespace modelnet {

// An overlapping timeout is held.
SwarmOverlapHoldResult SwarmHoldOverlap(const SwarmOverlapHold& edge, std::string& err)
{
    SwarmOverlapHoldResult out;
    out.claimed = false;
    out.atoms = 0;
    if (edge.edge_id.empty()) {
        out.code = "EDGE";
        err = "EDGE";
        return out;
    }
    if (edge.overlapping) {
        out.code = "TIMEOUT";
        err = "TIMEOUT";
        return out;
    }
    if (edge.want_claim) {
        out.code = "HELD";
        err = "HELD";
        return out;
    }
    out.code = "NOTED";
    err.clear();
    return out;
}

} // namespace modelnet
