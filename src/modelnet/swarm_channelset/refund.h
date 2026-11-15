// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_CHANNELSET_REFUND_H
#define BITCOIN_MODELNET_SWARM_CHANNELSET_REFUND_H

#include <modelnet/swarm_channelset/record.h>

#include <string>

namespace modelnet {

/**
 * Build the in-memory refund by calling SwarmBuildRefund.
 * refund_height is stored on the channel so a later payout can name the
 * same expiry. SwarmBuildPayout refuses a different expiry.
 * No channel is CHANNEL. A second call is REPLAY and leaves the first
 * refund in place. The template is not broadcast and is not mined.
 */
bool ChannelSetRefund(ChannelSetRecord& record, int refund_height, std::string& err);

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_CHANNELSET_REFUND_H
