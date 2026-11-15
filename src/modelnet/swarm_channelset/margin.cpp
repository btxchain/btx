// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_channelset/margin.h>

#include <modelnet/swarm_paymesh.h>

namespace modelnet {

bool ChannelSetMarginOpen(int height, int refund_height)
{
    return SwarmClaimBeforeRefund(height, refund_height);
}

} // namespace modelnet
