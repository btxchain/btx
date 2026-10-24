// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnopqone2.h>

namespace modelnet {

SwarmNotNoPqOne2Result SwarmNoteNotNoPqOne2(const SwarmNotNoPqOne2& note, std::string& err)
{
    SwarmNotNoPqOne2Result result;
    result.added = false;
    // The payment mesh stays one.
    if (note.mesh_id.empty()) {
        result.code = "MESH";
        result.added = false;
        err = "MESH";
        return result;
    }
    if (note.want_add) {
        result.code = "HELD";
        result.added = false;
        err = "HELD";
        return result;
    }
    result.code = "NOTED";
    result.added = false;
    err.clear();
    return result;
}

} // namespace modelnet
