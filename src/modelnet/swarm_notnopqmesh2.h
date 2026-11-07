// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_NOTNOPQMESH2_H
#define BTX_MODELNET_SWARM_NOTNOPQMESH2_H

#include <string>

namespace modelnet {

/**
 * A local note about one PQ payment mesh. many_pools names several pools
 * on that same mesh. want_split asks this note to split the mesh.
 *
 * One PQ payment mesh stays one mesh for many pools. This note splits
 * none. split stays false on every path.
 */
struct SwarmNotNoPqMesh2 {
    std::string mesh_id;
    bool many_pools{false};
    bool want_split{false};
};

/**
 * Outcome of noting a PQ payment mesh. split stays false on every path.
 * One PQ payment mesh stays one mesh for many pools.
 */
struct SwarmNotNoPqMesh2Result {
    std::string code;
    bool split{false};
};

/**
 * Note one PQ payment mesh without splitting it.
 * Order, first match wins: an empty mesh_id is MESH. many_pools is STAYS
 * even when want_split is false. want_split is HELD. Otherwise the note is
 * NOTED and err is clear. split stays false on every path. One PQ payment
 * mesh stays one mesh for many pools.
 */
SwarmNotNoPqMesh2Result SwarmNoteNotNoPqMesh2(const SwarmNotNoPqMesh2& note, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_NOTNOPQMESH2_H
