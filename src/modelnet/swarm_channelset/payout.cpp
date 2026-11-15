// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_channelset/payout.h>

#include <modelnet/swarm_channelset/error.h>
#include <modelnet/swarm_channelset/margin.h>
#include <modelnet/swarm_paymesh.h>

namespace modelnet {

bool ChannelSetPayout(ChannelSetRecord& record, int64_t cumulative, int height, int refund_height, std::string& err)
{
    if (!record.tx.funded) {
        err = kChannelSetNotFunded;
        return false;
    }
    if (!ChannelSetMarginOpen(height, refund_height)) {
        err = kChannelSetMargin;
        return false;
    }
    if (cumulative > record.tx.capacity) {
        err = kChannelSetShort;
        return false;
    }
    if (record.payouts > 0 && cumulative < record.tx.cumulative) {
        err = kChannelSetStale;
        return false;
    }
    if (!SwarmBuildPayout(record.tx, cumulative, height, refund_height, err)) {
        return false;
    }
    record.payouts += 1;
    return true;
}

} // namespace modelnet
