// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_PQMESH_H
#define BITCOIN_MODELNET_SWARM_PQMESH_H

#include <cstdint>
#include <string>

namespace modelnet {

struct SwarmPqMesh {
    std::string mesh_id;
    bool want_add;
};

struct SwarmPqMeshResult {
    std::string code;
    bool added;
    int64_t meshes;
};

SwarmPqMeshResult SwarmKeepPaymentMesh(const SwarmPqMesh& mesh, std::string& err);

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_PQMESH_H
