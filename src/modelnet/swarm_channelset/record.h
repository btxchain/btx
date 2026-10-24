// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_CHANNELSET_RECORD_H
#define BITCOIN_MODELNET_SWARM_CHANNELSET_RECORD_H

#include <modelnet/swarm_paymesh.h>

#include <string>

namespace modelnet {

/**
 * One in-memory channel. The SwarmChannelTx templates are never broadcast
 * and never mined. No spend key is stored. payouts counts successful
 * SwarmBuildPayout calls so a later lower cumulative can be refused.
 */
struct ChannelSetRecord {
    bool opened{false};
    bool refund_built{false};
    int payouts{0};
    std::string name;
    SwarmChannelTx tx;
};

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_CHANNELSET_RECORD_H
