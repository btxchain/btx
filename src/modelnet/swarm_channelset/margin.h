// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_CHANNELSET_MARGIN_H
#define BITCOIN_MODELNET_SWARM_CHANNELSET_MARGIN_H

namespace modelnet {

/**
 * True when a payout at height is still before the refund.
 * The window is SwarmClaimBeforeRefund: refund_height must sit more than
 * SWARM_CLOSE_MARGIN (160) blocks above height. A gap of 160 is closed.
 */
bool ChannelSetMarginOpen(int height, int refund_height);

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_CHANNELSET_MARGIN_H
