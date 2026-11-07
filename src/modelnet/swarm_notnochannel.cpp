// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnochannel.h>

#include <cstdint>
#include <string>

namespace modelnet {

SwarmNotNoChannelResult SwarmNoteNotNoChannel(const SwarmNotNoChannel& note, std::string& err)
{
    SwarmNotNoChannelResult result;
    result.opened = false;
    result.channels = 0;
    // High-speed L2 stays one channel for many pools, and this note opens no second channel.
    if (note.channel_id.empty()) {
        result.code = "CHANNEL";
        result.opened = false;
        result.channels = 0;
        err = "CHANNEL";
        return result;
    }
    if (note.want_open_second) {
        result.code = "ONE_CHANNEL";
        result.opened = false;
        result.channels = 0;
        err = "ONE_CHANNEL";
        return result;
    }
    result.code = "NOTED";
    result.opened = false;
    result.channels = 0;
    err.clear();
    return result;
}

} // namespace modelnet
