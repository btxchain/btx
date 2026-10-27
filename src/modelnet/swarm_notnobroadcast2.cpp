// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnobroadcast2.h>

#include <string>

namespace modelnet {

SwarmNotNoBroadcast2Result SwarmNoteNotNoBroadcast2(const SwarmNotNoBroadcast2& note, std::string& err)
{
    SwarmNotNoBroadcast2Result result;
    result.broadcast = false;
    // Nothing is broadcast to mainnet.
    if (note.tx_id.empty()) {
        result.code = "TX";
        result.broadcast = false;
        err = "TX";
        return result;
    }
    if (note.want_broadcast) {
        result.code = "HELD";
        result.broadcast = false;
        err = "HELD";
        return result;
    }
    result.code = "NOTED";
    result.broadcast = false;
    err.clear();
    return result;
}

} // namespace modelnet
