// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_NOTMESH_H
#define BTX_MODELNET_SWARM_NOTMESH_H

#include <string>

namespace modelnet {

/**
 * A local note about one mesh. want_open asks this note to open a mesh.
 *
 * There is one post-quantum payment mesh for many pools. This note does
 * not open a mesh or broadcast. opened and broadcast stay false on every
 * path.
 */
struct SwarmNotMesh {
    std::string mesh_id;
    int mesh_count{0};
    bool want_open{false};
};

/**
 * Outcome of noting a mesh. opened and broadcast stay false on every path.
 * There is one post-quantum payment mesh for many pools. This note does
 * not open a mesh or broadcast.
 */
struct SwarmNotMeshResult {
    std::string code;
    bool opened{false};
    bool broadcast{false};
};

/**
 * Note a mesh without opening it or broadcasting.
 * Order, first match wins: an empty mesh_id is MESH. mesh_count != 1 or
 * want_open is ONE_MESH. Otherwise the note is NOTED and err is clear.
 * opened and broadcast stay false on every path. There is one
 * post-quantum payment mesh for many pools. This note does not open a
 * mesh or broadcast.
 */
SwarmNotMeshResult SwarmNoteNotMesh(const SwarmNotMesh& note, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_NOTMESH_H
