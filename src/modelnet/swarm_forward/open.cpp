// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_forward/open.h>

#include <modelnet/swarm_forward/codes.h>

namespace modelnet {

bool SwarmForwardOpen::Accept(const std::string& channel, int64_t liquidity, std::string& err) const
{
    if (channel.empty()) {
        err = kSwarmForwardChannel;
        return false;
    }
    if (liquidity < 1) {
        err = kSwarmForwardLiquidity;
        return false;
    }
    err.clear();
    return true;
}

} // namespace modelnet
