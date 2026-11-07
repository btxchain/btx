// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnopqmesh2.h>

namespace modelnet {

SwarmNotNoPqMesh2Result SwarmNoteNotNoPqMesh2(const SwarmNotNoPqMesh2& note, std::string& err)
{
    SwarmNotNoPqMesh2Result result;
    result.split = false;
    // One PQ payment mesh stays one mesh for many pools.
    if (note.mesh_id.empty()) {
        result.code = "MESH";
        result.split = false;
        err = "MESH";
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
