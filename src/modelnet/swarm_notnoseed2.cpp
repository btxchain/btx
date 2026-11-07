// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnoseed2.h>

#include <string>

namespace modelnet {

SwarmNotNoSeed2Result SwarmNoteNotNoSeed2(const SwarmNotNoSeed2& note, std::string& err)
{
    SwarmNotNoSeed2Result result;
    result.disabled = false;
    // Public seeding stays on. This note does not disable it.
    if (note.node_id.empty()) {
        result.code = "NODE";
        result.disabled = false;
        err = "NODE";
        return result;
    }
    if (note.want_disable) {
        result.code = "HELD";
        result.disabled = false;
        err = "HELD";
        return result;
    }
    result.code = "NOTED";
    result.disabled = false;
    err.clear();
    return result;
}

} // namespace modelnet
