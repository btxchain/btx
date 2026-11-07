// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnol2one2.h>

#include <string>

namespace modelnet {

SwarmNotNoL2One2Result SwarmNoteNotNoL2One2(const SwarmNotNoL2One2& note, std::string& err)
{
    SwarmNotNoL2One2Result result;
    result.split = false;
    // High-speed L2 stays one channel for many pools.
    if (note.channel_id.empty()) {
        result.code = "CHANNEL";
        result.split = false;
        err = "CHANNEL";
        return result;
    }
    if (note.many_pools) {
        result.code = "STAYS";
        result.split = false;
        err = "STAYS";
        return result;
    }
    if (note.want_split) {
        result.code = "HELD";
        result.split = false;
        err = "HELD";
        return result;
    }
    result.code = "NOTED";
    result.split = false;
    err.clear();
    return result;
}

} // namespace modelnet
