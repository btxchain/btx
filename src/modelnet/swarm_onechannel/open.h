// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_ONECHANNEL_OPEN_H
#define BITCOIN_MODELNET_SWARM_ONECHANNEL_OPEN_H

#include <modelnet/swarm_onechannel/record.h>

#include <string>

namespace modelnet {

/**
 * Classify a request to open the network channel.
 * The function always sets err to NOT_OPENED and returns false.
 * A reserved channel id on seat is not a network open.
 * The seat is not modified. Nothing is broadcast.
 */
bool SwarmOneChannelClassifyOpen(const SwarmOneChannelSeat& seat, std::string& err);

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_ONECHANNEL_OPEN_H
