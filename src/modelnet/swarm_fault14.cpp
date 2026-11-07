// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_fault14.h>

namespace modelnet {

SwarmFault14Result SwarmRecoverFault14(const SwarmFault14& in, std::string& err)
{
    SwarmFault14Result result;
    // A refund that reaches maturity during a network disruption is not live.
    result.refunded = false;
    result.broadcast = false;
    result.committed = false;

    if (in.channel_id.empty()) {
        result.code = "CHANNEL";
        result.refunded = false;
        result.broadcast = false;
        result.committed = false;
        err = "CHANNEL";
        return result;
    }
    if (!in.refund_signed) {
        result.code = "UNSIGNED";
        result.refunded = false;
        result.broadcast = false;
        result.committed = false;
        err = "UNSIGNED";
        return result;
    }
    if (in.want_broadcast) {
        result.code = "HELD";
        result.refunded = false;
        result.broadcast = false;
        result.committed = false;
        err.clear();
        return result;
    }
    if (in.disrupted || in.mature) {
        result.code = "NOT_LIVE";
        result.refunded = false;
        result.broadcast = false;
        result.committed = false;
        err = "NOT_LIVE";
        return result;
    }
    result.code = "NOTED";
    result.refunded = false;
    result.broadcast = false;
    result.committed = false;
    err.clear();
    return result;
}

} // namespace modelnet
