// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_forward/margin.h>

#include <modelnet/swarm_forward/codes.h>
#include <modelnet/swarm_paymesh.h>

namespace modelnet {

bool SwarmForwardMargin::Accept(int incoming_expiry, int outgoing_expiry, std::string& err) const
{
    // First argument is the outgoing expiry. SwarmRouteMargin then reports
    // MARGIN when outgoing_expiry < incoming_expiry + 160.
    err.clear();
    if (!SwarmRouteMargin(outgoing_expiry, incoming_expiry, kSwarmForwardMarginBlocks, err)) {
        if (err.empty()) {
            err = kSwarmForwardMargin;
        }
        return false;
    }
    return true;
}

} // namespace modelnet
