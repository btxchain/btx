// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_CHANNELSET_CLAIM_H
#define BITCOIN_MODELNET_SWARM_CHANNELSET_CLAIM_H

namespace modelnet {

/**
 * Result of SwarmClaimBeforeRefund. This does not build a transaction,
 * broadcast, or mine.
 */
bool ChannelSetClaimAllowed(int height, int refund_height);

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_CHANNELSET_CLAIM_H
