// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_adminrefund.h>

#include <string>

namespace modelnet {

SwarmAdminRefundResult SwarmNoteAdminRefund(const SwarmAdminRefund& channel, std::string& err)
{
    SwarmAdminRefundResult result;
    result.moved = false;
    // An admin does not move the sponsor refund key.
    if (channel.channel_id.empty()) {
        result.code = "CHANNEL";
        result.moved = false;
        err = "CHANNEL";
        return result;
    }
    if (channel.admin) {
        result.code = "HELD";
        result.moved = false;
        err = "HELD";
        return result;
    }
    if (channel.want_move) {
        result.code = "HELD";
        result.moved = false;
        err = "HELD";
        return result;
    }
    result.code = "NOTED";
    result.moved = false;
    err.clear();
    return result;
}

} // namespace modelnet
