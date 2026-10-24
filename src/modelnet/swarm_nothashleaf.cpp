// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_nothashleaf.h>

#include <string>

namespace modelnet {

SwarmNotHashLeafResult SwarmNoteNotHashLeaf(const SwarmNotHashLeaf& note, std::string& err)
{
    SwarmNotHashLeafResult result;
    result.built = false;
    result.broadcast = false;
    // A contributor hashlock leaf is not built or broadcast by this note.
    if (note.channel_id.empty()) {
        result.code = "CHANNEL";
        result.built = false;
        result.broadcast = false;
        err = "CHANNEL";
        return result;
    }
    if (note.want_build) {
        result.code = "NOT_BUILT";
        result.built = false;
        result.broadcast = false;
        err = "NOT_BUILT";
        return result;
    }
    result.code = "NOTED";
    result.built = false;
    result.broadcast = false;
    err.clear();
    return result;
}

} // namespace modelnet
