// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notmesh.h>

#include <string>

namespace modelnet {

SwarmNotMeshResult SwarmNoteNotMesh(const SwarmNotMesh& note, std::string& err)
{
    SwarmNotMeshResult result;
    result.opened = false;
    result.broadcast = false;
    // There is one post-quantum payment mesh for many pools. This note does not open a mesh or broadcast.
    if (note.mesh_id.empty()) {
        result.code = "MESH";
        result.opened = false;
        result.broadcast = false;
        err = "MESH";
        return result;
    }
    if (note.mesh_count != 1 || note.want_open) {
        result.code = "ONE_MESH";
        result.opened = false;
        result.broadcast = false;
        err = "ONE_MESH";
        return result;
    }
    result.code = "NOTED";
    result.opened = false;
    result.broadcast = false;
    err.clear();
    return result;
}

} // namespace modelnet
