// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnopqmesh.h>

namespace modelnet {

SwarmNotNoPqMeshResult SwarmNoteNotNoPqMesh(const SwarmNotNoPqMesh& note, std::string& err)
{
    SwarmNotNoPqMeshResult result;
    result.opened = false;
    result.meshes = 0;
    // There is one PQ payment mesh. This note opens none.
    if (note.mesh_id.empty()) {
        result.code = "MESH";
        result.opened = false;
        result.meshes = 0;
        err = "MESH";
        return result;
    }
    if (note.mesh_count != 1) {
        result.code = "ONE_MESH";
        result.opened = false;
        result.meshes = 0;
        err = "ONE_MESH";
        return result;
    }
    if (note.want_second) {
        result.code = "ONE_MESH";
        result.opened = false;
        result.meshes = 0;
        err = "ONE_MESH";
        return result;
    }
    result.code = "NOTED";
    result.opened = false;
    result.meshes = 0;
    err.clear();
    return result;
}

} // namespace modelnet
