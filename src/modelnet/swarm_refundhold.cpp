// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_refundhold.h>

#include <cstdint>

namespace modelnet {
namespace {

SwarmRefundHoldResult Deny(const std::string& code, std::string& err)
{
    SwarmRefundHoldResult result;
    result.mature = false;
    result.broadcast = false;
    result.code = code;
    err = code;
    return result;
}

SwarmRefundHoldResult Hold(const std::string& code, std::string& err)
{
    SwarmRefundHoldResult result;
    result.mature = true;
    result.broadcast = false;
    result.code = code;
    err.clear();
    return result;
}

} // namespace

SwarmRefundHoldResult SwarmHoldRefund(const SwarmRefundHoldRequest& request, std::string& err)
{
    if (request.height < 0 || request.refund_height < 1) {
        return Deny("REFUND", err);
    }
    if (request.want_broadcast) {
        return Deny("BROADCAST_FORBIDDEN", err);
    }
    if (request.height < request.refund_height) {
        return Deny("EARLY", err);
    }
    if (request.disrupted) {
        return Hold("DISRUPTED", err);
    }
    return Hold("MATURE", err);
}

} // namespace modelnet
