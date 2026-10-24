// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notmainnet.h>

#include <string>

namespace modelnet {

SwarmNotMainnetResult SwarmNoteNotMainnet(const SwarmNotMainnet& note, std::string& err)
{
    SwarmNotMainnetResult result;
    result.broadcast = false;
    result.mined = false;
    // This note does not broadcast or mine.
    if (note.request_id.empty()) {
        result.code = "REQUEST";
        result.broadcast = false;
        result.mined = false;
        err = "REQUEST";
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
