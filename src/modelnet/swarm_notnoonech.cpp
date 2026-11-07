// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnoonech.h>

#include <string>

namespace modelnet {

SwarmNotNoOneChResult SwarmNoteNotNoOneCh(const SwarmNotNoOneCh& note, std::string& err)
{
    SwarmNotNoOneChResult result;
    result.opened = false;
    result.channels = 0;
    // High-speed L2 is one channel for many pools. This note opens no second channel.
    if (note.pool_id.empty()) {
        result.code = "POOL";
        result.opened = false;
        result.channels = 0;
        err = "POOL";
        return result;
    }
    if (note.want_open) {
        result.code = "ONE";
        result.opened = false;
        result.channels = 0;
        err = "ONE";
        return result;
    }
    result.code = "NOTED";
    result.opened = false;
    result.channels = 0;
    err.clear();
    return result;
}

} // namespace modelnet
