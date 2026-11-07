// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_CHANNELSET_PAYOUT_H
#define BITCOIN_MODELNET_SWARM_CHANNELSET_PAYOUT_H

#include <modelnet/swarm_channelset/record.h>

#include <cstdint>
#include <string>

namespace modelnet {

/**
 * Pay a nondecreasing cumulative on a funded channel.
 * An unfunded channel is NOT_FUNDED and builds nothing.
 * A refund height that is not beyond the 160-block close margin is MARGIN
 * and builds nothing.
 * cumulative above capacity is SHORT and leaves the stored cumulative.
 * A second payout with a lower cumulative is STALE and leaves it too.
 * Otherwise SwarmBuildPayout builds the in-memory payout. It is not
 * broadcast and it is not mined.
 */
bool ChannelSetPayout(ChannelSetRecord& record, int64_t cumulative, int height, int refund_height, std::string& err);

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_CHANNELSET_PAYOUT_H
