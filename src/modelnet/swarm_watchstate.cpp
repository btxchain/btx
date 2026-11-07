// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_watchstate.h>

namespace modelnet {

SwarmWatchStateResult SwarmWatchChannel(const SwarmWatchState& watch, std::string& err)
{
    // A channel watch can name a stale state. It does not penalize or broadcast.
    SwarmWatchStateResult result;
    result.penalized = false;
    result.broadcast = false;
    result.secp_penalty = false;
    if (watch.channel_id.empty()) {
        result.code = "CHANNEL";
        err = "CHANNEL";
        return result;
    }
    if (watch.stale) {
        result.code = "STALE";
        err = "STALE";
        return result;
    }
    if (watch.want_penalty || watch.want_broadcast) {
        result.code = "HELD";
        err = "HELD";
        return result;
    }
    result.code = "NOTED";
    err.clear();
    return result;
}

} // namespace modelnet
