// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_NOTNOPQMESH_H
#define BTX_MODELNET_SWARM_NOTNOPQMESH_H

#include <cstdint>
#include <string>

namespace modelnet {

/**
 * A local note about one PQ payment mesh. want_second asks this note for a
 * second mesh.
 *
 * There is one PQ payment mesh. This note opens none. opened stays false
 * and meshes stays 0 on every path.
 */
struct SwarmNotNoPqMesh {
    std::string mesh_id;
    int64_t mesh_count{0};
    bool want_second{false};
};

/**
 * Outcome of noting a PQ payment mesh. opened stays false and meshes stays
 * 0 on every path. There is one PQ payment mesh. This note opens none.
 */
struct SwarmNotNoPqMeshResult {
    std::string code;
    bool opened{false};
    int64_t meshes{0};
};

/**
 * Note one PQ payment mesh without opening any.
 * Order, first match wins: an empty mesh_id is MESH. mesh_count not exactly
 * 1 is ONE_MESH even when want_second is false. want_second is ONE_MESH.
 * Otherwise the note is NOTED and err is clear. opened stays false and
 * meshes stays 0 on every path. There is one PQ payment mesh. This note
 * opens none.
 */
SwarmNotNoPqMeshResult SwarmNoteNotNoPqMesh(const SwarmNotNoPqMesh& note, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_NOTNOPQMESH_H
