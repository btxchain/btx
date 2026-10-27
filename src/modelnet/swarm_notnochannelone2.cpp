// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnochannelone2.h>

#include <string>

namespace modelnet {

SwarmNotNoChannelOne2Result SwarmNoteNotNoChannelOne2(const SwarmNotNoChannelOne2& note, std::string& err)
{
    SwarmNotNoChannelOne2Result result;
    result.opened = false;
    // High-speed L2 stays one channel.
    if (note.channel_id.empty()) {
        result.code = "CHANNEL";
        result.opened = false;
        err = "CHANNEL";
        return result;
    }
    if (note.second_channel) {
        result.code = "NOT_OPENED";
        result.opened = false;
        err = "NOT_OPENED";
        return result;
    }
    if (note.want_open) {
        result.code = "HELD";
        result.opened = false;
        err = "HELD";
        return result;
    }
    result.code = "NOTED";
    result.opened = false;
    err.clear();
    return result;
}

} // namespace modelnet
