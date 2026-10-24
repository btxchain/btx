// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnoprivateoff2.h>

namespace modelnet {

SwarmNotNoPrivateOff2Result SwarmNoteNotNoPrivateOff2(const SwarmNotNoPrivateOff2& note, std::string& err)
{
    // Without a device file, private prompts stay off.
    SwarmNotNoPrivateOff2Result result;
    result.enabled = false;

    if (note.node_id.empty()) {
        result.code = "NODE";
        err = "NODE";
        result.enabled = false;
        return result;
    }
    if (note.no_device) {
        result.code = "NOT_PRIVATE";
        err = "NOT_PRIVATE";
        result.enabled = false;
        return result;
    }
    if (note.want_enable) {
        result.code = "HELD";
        err = "HELD";
        result.enabled = false;
        return result;
    }
    result.code = "NOTED";
    err.clear();
    result.enabled = false;
    return result;
}

} // namespace modelnet
