// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_ONECHANNEL_RESERVE_H
#define BITCOIN_MODELNET_SWARM_ONECHANNEL_RESERVE_H

#include <modelnet/swarm_onechannel/record.h>

#include <string>

namespace modelnet {

/**
 * Decide whether channel may be stored on the one seat.
 * An empty channel sets err to CHANNEL. The seat is not written here.
 * The same id already on the seat sets err to REPLAY.
 * A different id, once the seat is taken, sets err to NOT_OPENED.
 * The first non-empty id clears err and returns true.
 * A reserved id is not a network open. This decision does not open one.
 */
bool SwarmOneChannelDecideReserve(const SwarmOneChannelSeat& seat, const std::string& channel, std::string& err);

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_ONECHANNEL_RESERVE_H
