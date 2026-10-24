// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnoclose160.h>

namespace modelnet {

SwarmNotNoClose160Result SwarmNoteNotNoClose160(const SwarmNotNoClose160& note, std::string& err)
{
    SwarmNotNoClose160Result result;
    result.closed = false;
    result.height = 0;
    // The close margin stays 160 blocks. This note closes nothing.
    if (note.channel_id.empty()) {
        result.code = "CHANNEL";
        result.closed = false;
        result.height = 0;
        err = "CHANNEL";
        return result;
    }
    if (note.want_close) {
        result.code = "HELD";
        result.closed = false;
        result.height = 0;
        err = "HELD";
        return result;
    }
    result.code = "NOTED";
    result.closed = false;
    result.height = 0;
    err.clear();
    return result;
}

} // namespace modelnet
