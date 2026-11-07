// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnopool.h>

#include <string>

namespace modelnet {

SwarmNotNoPoolResult SwarmNoteNotNoPool(const SwarmNotNoPool& note, std::string& err)
{
    SwarmNotNoPoolResult result;
    result.opened = false;
    result.meshes = 0;
    // Many pools stay on one payment mesh, and this note opens no mesh.
    if (note.pool_id.empty()) {
        result.code = "POOL";
        result.opened = false;
        result.meshes = 0;
        err = "POOL";
        return result;
    }
    if (note.want_open_mesh) {
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
