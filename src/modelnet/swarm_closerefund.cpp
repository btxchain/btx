// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_closerefund.h>

#include <cstdint>
#include <string>

namespace modelnet {

SwarmCloseRefundResult SwarmRecordClose(const SwarmCloseRefund& close, std::string& err)
{
    SwarmCloseRefundResult result;
    result.shrunk = false;
    result.broadcast = false;
    result.blocks = 160;
    // The close margin stays 160 blocks. This record does not broadcast.
    if (close.channel_id.empty()) {
        result.code = "CHANNEL";
        result.shrunk = false;
        result.broadcast = false;
        result.blocks = 160;
        err = "CHANNEL";
        return result;
    }
    if (close.margin != 160) {
        result.code = "MARGIN";
        result.shrunk = false;
        result.broadcast = false;
        result.blocks = 160;
        err = "MARGIN";
        return result;
    }
    if (close.want_shrink || close.want_broadcast) {
        result.code = "HELD";
        result.shrunk = false;
        result.broadcast = false;
        result.blocks = 160;
        err = "HELD";
        return result;
    }
    result.code = "NOTED";
    result.shrunk = false;
    result.broadcast = false;
    result.blocks = 160;
    err.clear();
    return result;
}

} // namespace modelnet
