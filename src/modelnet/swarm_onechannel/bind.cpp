// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_onechannel/bind.h>

#include <modelnet/swarm_onechannel/codes.h>

#include <string>

namespace modelnet {

bool SwarmOneChannelDecideBind(bool channel_reserved, bool already_bound, const std::string& pool, std::string& err)
{
    if (pool.empty()) {
        err = SWARM_ONECHANNEL_POOL;
        return false;
    }
    if (!channel_reserved) {
        err = SWARM_ONECHANNEL_CHANNEL;
        return false;
    }
    if (already_bound) {
        err = SWARM_ONECHANNEL_REPLAY;
        return false;
    }
    err.clear();
    return true;
}

} // namespace modelnet
