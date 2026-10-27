// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_nobroadcast.h>

namespace modelnet {

SwarmNoBroadcastResult SwarmNoteNoBroadcast(const SwarmNoBroadcast& note, std::string& err)
{
    SwarmNoBroadcastResult result;
    result.broadcast = false;
    if (note.channel_id.empty()) {
        result.code = "BROADCAST";
        result.broadcast = false;
        err = "BROADCAST";
        return result;
    }
    // Nothing is broadcast on mainnet.
    if (note.want_mainnet) {
        result.code = "MAINNET";
        result.broadcast = false;
        err = "MAINNET";
        return result;
    }
    result.code = "NOTED";
    result.broadcast = false;
    err.clear();
    return result;
}

} // namespace modelnet
