// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_ONECHANNEL_RECORD_H
#define BITCOIN_MODELNET_SWARM_ONECHANNEL_RECORD_H

#include <cstdint>
#include <string>

namespace modelnet {

/**
 * The one channel seat.
 * reserved is true only together with a non-empty channel_id.
 * The seat has no network-open bit, no broadcast bit, and no spend bit.
 */
struct SwarmOneChannelSeat {
    bool reserved{false};
    std::string channel_id;
};

/**
 * One pool bound to the single channel.
 * funded and holds_money start false. quote starts empty. atoms start at 0.
 * The row has no broadcast bit and no network-open bit.
 */
struct SwarmOneChannelPool {
    std::string pool_id;
    std::string channel_id;
    bool funded{false};
    bool holds_money{false};
    std::string quote;
    int64_t atoms{0};
};

/** True when the seat holds a non-empty channel id. */
bool SwarmOneChannelSeatReserved(const SwarmOneChannelSeat& seat);

/** True when the seat is reserved and already holds this channel id. */
bool SwarmOneChannelSeatSame(const SwarmOneChannelSeat& seat, const std::string& channel);

/**
 * True when row is bound to channel.
 * The pool id and the channel id are both non-empty, and the channel id matches.
 */
bool SwarmOneChannelPoolOnChannel(const SwarmOneChannelPool& row, const std::string& channel);

/**
 * Build an unfunded pool row bound to channel.
 * An empty pool sets err to POOL and leaves created unchanged.
 * An empty channel sets err to CHANNEL and leaves created unchanged.
 * A usable row starts unfunded, holds no money, has an empty quote, and has zero atoms.
 */
bool SwarmOneChannelMakePool(const std::string& pool,
                             const std::string& channel,
                             SwarmOneChannelPool& created,
                             std::string& err);

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_ONECHANNEL_RECORD_H
