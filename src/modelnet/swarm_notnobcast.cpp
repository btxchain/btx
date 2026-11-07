// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnobcast.h>

#include <string>

namespace modelnet {

SwarmNotNoBcastResult SwarmNoteNotNoBcast(const SwarmNotNoBcast& note, std::string& err)
{
    SwarmNotNoBcastResult result;
    result.broadcast = false;
    result.mined = false;
    // This note does not broadcast to mainnet.
    if (note.tx_id.empty()) {
        result.code = "TX";
        result.broadcast = false;
        result.mined = false;
        err = "TX";
        return result;
    }
    if (note.want_mainnet) {
        result.code = "MAINNET";
        result.broadcast = false;
        result.mined = false;
        err = "MAINNET";
        return result;
    }
    result.code = "NOTED";
    result.broadcast = false;
    result.mined = false;
    err.clear();
    return result;
}

} // namespace modelnet
