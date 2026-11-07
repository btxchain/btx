// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_channelset/refund.h>

#include <modelnet/swarm_channelset/error.h>
#include <modelnet/swarm_paymesh.h>

namespace modelnet {

bool ChannelSetRefund(ChannelSetRecord& record, int refund_height, std::string& err)
{
    if (!record.opened) {
        err = kChannelSetChannel;
        return false;
    }
    if (record.refund_built) {
        err = kChannelSetReplay;
        return false;
    }

    const int prior_height = record.tx.refund_height;
    record.tx.refund_height = refund_height;
    if (!SwarmBuildRefund(record.tx, err)) {
        record.tx.refund_height = prior_height;
        record.refund_built = false;
        return false;
    }
    record.refund_built = true;
    err.clear();
    return true;
}

} // namespace modelnet
