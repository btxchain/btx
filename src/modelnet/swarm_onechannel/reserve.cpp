// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_onechannel/reserve.h>

#include <modelnet/swarm_onechannel/codes.h>
#include <modelnet/swarm_onechannel/limits.h>
#include <modelnet/swarm_onechannel/record.h>

#include <string>

namespace modelnet {

bool SwarmOneChannelDecideReserve(const SwarmOneChannelSeat& seat, const std::string& channel, std::string& err)
{
    if (channel.empty()) {
        err = SWARM_ONECHANNEL_CHANNEL;
        return false;
    }
    if (SwarmOneChannelSeatSame(seat, channel)) {
        err = SWARM_ONECHANNEL_REPLAY;
        return false;
    }
    const int occupied = SwarmOneChannelSeatReserved(seat) ? 1 : 0;
    if (occupied + 1 > kSwarmOneChannelSeatLimit) {
        err = SWARM_ONECHANNEL_NOT_OPENED;
        return false;
    }
    err.clear();
    return true;
}

} // namespace modelnet
