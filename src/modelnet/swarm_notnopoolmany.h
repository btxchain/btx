// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_NOTNOPOOLMANY_H
#define BTX_MODELNET_SWARM_NOTNOPOOLMANY_H

#include <string>

namespace modelnet {

/**
 * A local note about one payment mesh that serves many pools.
 * want_split asks this note to split the mesh.
 *
 * One PQ payment mesh serves many pools. This note does not split the mesh.
 * split stays false and meshes stays 0 on every path.
 */
struct SwarmNotNoPoolMany {
    std::string mesh_id;
    bool want_split{false};
};

/**
 * Outcome of noting a payment mesh that serves many pools.
 * split stays false and meshes stays 0 on every path.
 * One PQ payment mesh serves many pools. This note does not split the mesh.
 */
struct SwarmNotNoPoolManyResult {
    std::string code;
    bool split{false};
    int meshes{0};
};

/**
 * Note one payment mesh that serves many pools, without splitting it.
 * Order, first match wins: an empty mesh_id is MESH. want_split is ONE.
 * Otherwise the note is NOTED and err is clear.
 * split stays false and meshes stays 0 on every path.
 * One PQ payment mesh serves many pools. This note does not split the mesh.
 */
SwarmNotNoPoolManyResult SwarmNoteNotNoPoolMany(const SwarmNotNoPoolMany& note, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_NOTNOPOOLMANY_H
