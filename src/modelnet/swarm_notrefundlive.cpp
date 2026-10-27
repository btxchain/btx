// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notrefundlive.h>

#include <string>

namespace modelnet {

SwarmNotRefundLiveResult SwarmNoteNotRefundLive(const SwarmNotRefundLive& note, std::string& err)
{
    SwarmNotRefundLiveResult result;
    result.refunded = false;
    result.broadcast = false;
    // A refund reaching maturity during a network disruption is not a live channel.
    if (note.channel_id.empty()) {
        result.code = "CHANNEL";
        result.refunded = false;
        result.broadcast = false;
        err = "CHANNEL";
        return result;
    }
    if (note.want_refund) {
        result.code = "NOT_LIVE";
        result.refunded = false;
        result.broadcast = false;
        err = "NOT_LIVE";
        return result;
    }
    result.code = "NOTED";
    result.refunded = false;
    result.broadcast = false;
    err.clear();
    return result;
}

} // namespace modelnet
