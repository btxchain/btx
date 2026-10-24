// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_pqmesh.h>

namespace modelnet {

// The payment mesh stays one.
SwarmPqMeshResult SwarmKeepPaymentMesh(const SwarmPqMesh& mesh, std::string& err)
{
    SwarmPqMeshResult out;
    out.added = false;
    out.meshes = 1;
    if (mesh.mesh_id.empty()) {
        out.code = "MESH";
        err = "MESH";
        return out;
    }
    if (mesh.want_add) {
        out.code = "HELD";
        err = "HELD";
        return out;
    }
    out.code = "NOTED";
    err.clear();
    return out;
}

} // namespace modelnet
