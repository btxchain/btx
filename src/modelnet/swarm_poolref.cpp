// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_poolref.h>

namespace modelnet {

SwarmPoolChannelResult SwarmNotePoolChannel(const SwarmPoolChannel& channel, std::string& err)
{
    SwarmPoolChannelResult result;
    result.opened = false;
    if (channel.outpoint.empty() || channel.pool_id.empty()) {
        result.opened = false;
        result.code = "CHANNEL";
        err = "CHANNEL";
        return result;
    }
    // A second pool cannot open another channel on the same outpoint.
    // This wins even when want_reference is true. Nothing is broadcast.
    if (channel.want_open && channel.already_owned) {
        result.opened = false;
        result.code = "COLLATERAL_REUSE";
        err = "COLLATERAL_REUSE";
        return result;
    }
    // This note does not open a channel and does not broadcast.
    if (channel.want_open) {
        result.opened = false;
        result.code = "HELD";
        err.clear();
        return result;
    }
    if (channel.want_reference && !channel.already_owned) {
        result.opened = false;
        result.code = "NO_CHANNEL";
        err = "NO_CHANNEL";
        return result;
    }
    // A reference of an already owned channel is NOTED and still does
    // not open. Nothing is broadcast.
    result.opened = false;
    result.code = "NOTED";
    err.clear();
    return result;
}

} // namespace modelnet
