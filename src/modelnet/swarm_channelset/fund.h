// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_CHANNELSET_FUND_H
#define BITCOIN_MODELNET_SWARM_CHANNELSET_FUND_H

#include <modelnet/swarm_channelset/record.h>

#include <string>

namespace modelnet {

/**
 * Note funding on the in-memory channel by calling SwarmNoteChannelFunding.
 * No channel is CHANNEL. A second successful fund is REPLAY.
 * Funding before the refund is signed returns the paymesh error and
 * leaves the channel unfunded. This does not broadcast and does not mine.
 */
bool ChannelSetFund(ChannelSetRecord& record, std::string& err);

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_CHANNELSET_FUND_H
