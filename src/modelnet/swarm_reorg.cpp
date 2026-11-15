// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_reorg.h>

#include <algorithm>

namespace modelnet {

bool SwarmNoteReorg(SwarmReorgChannel& channel, int new_confirmations, SwarmReorgResult& result)
{
    channel.in_flight_released = false;
    if (!channel.broadcast) {
        result.code = "REORG_NO_BROADCAST";
        channel.confirmations = 0;
        channel.confirmed = false;
        channel.in_flight_released = false;
        return false;
    }
    if (new_confirmations < 0) {
        result.code = "REORG";
        channel.confirmed = false;
        channel.in_flight_released = false;
        return false;
    }
    channel.confirmations = std::min(channel.confirmations, new_confirmations);
    channel.confirmed = false;
    channel.in_flight_released = false;
    result.code = "REORG_HELD";
    return true;
}

} // namespace modelnet
