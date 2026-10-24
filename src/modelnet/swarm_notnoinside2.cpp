// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnoinside2.h>

#include <string>

namespace modelnet {

SwarmNotNoInside2Result SwarmNoteNotNoInside2(const SwarmNotNoInside2& note, std::string& err)
{
    SwarmNotNoInside2Result result;
    result.launched = false;
    // The swarm control plane stays inside btxd.
    if (note.node_id.empty()) {
        result.code = "NODE";
        result.launched = false;
        err = "NODE";
        return result;
    }
    if (note.want_exec) {
        result.code = "HELD";
        result.launched = false;
        err = "HELD";
        return result;
    }
    result.code = "NOTED";
    result.launched = false;
    err.clear();
    return result;
}

} // namespace modelnet
