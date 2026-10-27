// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnoclose1602.h>

#include <string>

namespace modelnet {

SwarmNotNoClose1602Result SwarmNoteNotNoClose1602(const SwarmNotNoClose1602& note, std::string& err)
{
    SwarmNotNoClose1602Result result;
    result.closed = false;
    // A close margin stays 160 blocks. This note closes nothing.
    if (note.channel_id.empty()) {
        result.code = "CHANNEL";
        result.closed = false;
        err = "CHANNEL";
        return result;
    }
    if (note.margin_blocks != 160) {
        result.code = "CAPPED";
        result.closed = false;
        err = "CAPPED";
        return result;
    }
    if (note.want_close) {
        result.code = "CAPPED";
        result.closed = false;
        err = "CAPPED";
        return result;
    }
    result.code = "NOTED";
    result.closed = false;
    err.clear();
    return result;
}

} // namespace modelnet
