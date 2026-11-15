// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_l2one.h>

#include <string>

namespace modelnet {

SwarmL2OneResult SwarmKeepOneChannel(const SwarmL2One& channel, std::string& err)
{
    SwarmL2OneResult result;
    result.opened = false;
    // A second high-speed channel is not opened.
    if (channel.channel_id.empty()) {
        result.code = "CHANNEL";
        result.opened = false;
        err = "CHANNEL";
        return result;
    }
    if (channel.second_channel) {
        result.code = "NOT_OPENED";
        result.opened = false;
        err = "NOT_OPENED";
        return result;
    }
    if (channel.want_open) {
        result.code = "HELD";
        result.opened = false;
        err = "HELD";
        return result;
    }
    result.code = "NOTED";
    result.opened = false;
    err.clear();
    return result;
}

} // namespace modelnet
