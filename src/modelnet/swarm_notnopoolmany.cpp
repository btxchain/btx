// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnopoolmany.h>

#include <string>

namespace modelnet {

SwarmNotNoPoolManyResult SwarmNoteNotNoPoolMany(const SwarmNotNoPoolMany& note, std::string& err)
{
    SwarmNotNoPoolManyResult result;
    result.split = false;
    result.meshes = 0;
    // One PQ payment mesh serves many pools. This note does not split the mesh.
    if (note.mesh_id.empty()) {
        result.code = "MESH";
        result.split = false;
        result.meshes = 0;
        err = "MESH";
        return result;
    }
    if (note.want_split) {
        result.code = "ONE";
        result.split = false;
        result.meshes = 0;
        err = "ONE";
        return result;
    }
    result.code = "NOTED";
    result.split = false;
    result.meshes = 0;
    err.clear();
    return result;
}

} // namespace modelnet
