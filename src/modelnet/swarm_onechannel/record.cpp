// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_onechannel/record.h>

#include <modelnet/swarm_onechannel/codes.h>
#include <modelnet/swarm_onechannel/limits.h>

#include <cstdint>
#include <string>

namespace modelnet {

bool SwarmOneChannelSeatReserved(const SwarmOneChannelSeat& seat)
{
    return seat.reserved && !seat.channel_id.empty();
}

bool SwarmOneChannelSeatSame(const SwarmOneChannelSeat& seat, const std::string& channel)
{
    return SwarmOneChannelSeatReserved(seat) && seat.channel_id == channel;
}

bool SwarmOneChannelPoolOnChannel(const SwarmOneChannelPool& row, const std::string& channel)
{
    return !row.pool_id.empty() && !row.channel_id.empty() && row.channel_id == channel;
}

bool SwarmOneChannelMakePool(const std::string& pool,
                             const std::string& channel,
                             SwarmOneChannelPool& created,
                             std::string& err)
{
    if (pool.empty()) {
        err = SWARM_ONECHANNEL_POOL;
        return false;
    }
    if (channel.empty()) {
        err = SWARM_ONECHANNEL_CHANNEL;
        return false;
    }
    SwarmOneChannelPool row;
    row.pool_id = pool;
    row.channel_id = channel;
    row.funded = false;
    row.holds_money = false;
    row.quote.clear();
    row.atoms = kSwarmOneChannelAtomsMoved;
    if (!SwarmOneChannelPoolOnChannel(row, channel) || row.pool_id != pool || row.funded || row.holds_money) {
        err = SWARM_ONECHANNEL_POOL;
        return false;
    }
    if (row.atoms != kSwarmOneChannelAtomsMoved || !row.quote.empty()) {
        err = SWARM_ONECHANNEL_POOL;
        return false;
    }
    created = row;
    err.clear();
    return true;
}

} // namespace modelnet
