// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_forward/allow.h>

#include <modelnet/swarm_forward/codes.h>
#include <modelnet/swarm_paymesh.h>

namespace modelnet {

bool SwarmForwardAllow::Accept(bool incoming_committed, int64_t liquidity, int64_t amount, int incoming_expiry, int height,
                               std::string& err) const
{
    err.clear();
    if (!SwarmForwardAllowed(incoming_committed, liquidity, amount, incoming_expiry, height, kSwarmForwardMarginBlocks,
                             err)) {
        if (err.empty()) {
            err = kSwarmForwardMargin;
        }
        return false;
    }
    return true;
}

} // namespace modelnet
