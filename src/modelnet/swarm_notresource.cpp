// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notresource.h>

namespace modelnet {

SwarmNotResourceResult SwarmNoteNotResource(const SwarmNotResource& note, std::string& err)
{
    SwarmNotResourceResult result;
    result.published = false;
    result.cpu_ms = 0;
    result.bytes = 0;
    if (note.node_id.empty()) {
        result.code = "NODE";
        result.published = false;
        result.cpu_ms = 0;
        result.bytes = 0;
        err = "NODE";
        return result;
    }
    if (note.want_publish) {
        result.code = "UNMEASURED";
        result.published = false;
        result.cpu_ms = 0;
        result.bytes = 0;
        err = "UNMEASURED";
        return result;
    }
    result.code = "NOTED";
    result.published = false;
    result.cpu_ms = 0;
    result.bytes = 0;
    err.clear();
    return result;
}

} // namespace modelnet
