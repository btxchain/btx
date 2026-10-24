// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnoclosemargin2.h>

#include <string>

namespace modelnet {

SwarmNotNoCloseMargin2Result SwarmNoteNotNoCloseMargin2(const SwarmNotNoCloseMargin2& note, std::string& err)
{
    SwarmNotNoCloseMargin2Result result;
    result.shrunk = false;
    result.blocks = 160;
    // The close margin stays 160 blocks.
    if (note.channel_id.empty()) {
        result.code = "CHANNEL";
        result.shrunk = false;
        result.blocks = 160;
        err = "CHANNEL";
        return result;
    }
    if (note.want_shrink) {
        result.code = "HELD";
        result.shrunk = false;
        result.blocks = 160;
        err = "HELD";
        return result;
    }
    result.code = "NOTED";
    result.shrunk = false;
    result.blocks = 160;
    err.clear();
    return result;
}

} // namespace modelnet
