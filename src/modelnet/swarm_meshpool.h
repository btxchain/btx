// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_MESHPOOL_H
#define BTX_MODELNET_SWARM_MESHPOOL_H

#include <string>

namespace modelnet {

/**
 * A local note that one payment mesh may carry many pools. mesh_id names
 * the mesh. pool_a and pool_b name two pools already on that mesh.
 * want_merge asks to fold those two pools onto one balance.
 *
 * The pools stay separate. This is a local note. Nothing is moved and
 * nothing is broadcast. No hostnames or IPs are used.
 */
struct SwarmMeshPools {
    std::string mesh_id;
    std::string pool_a;
    std::string pool_b;
    bool want_merge{false};
};

/**
 * A local mesh-pool note. merged stays false on every path: two pools
 * are never folded onto one balance.
 */
struct SwarmMeshPoolsResult {
    bool merged{false};
    std::string code;
};

/**
 * Order, first match wins: an empty mesh_id, an empty pool_a, or an
 * empty pool_b is MESH. pool_a equal to pool_b is SAME, including when
 * want_merge is true. want_merge is SEPARATE: two pools are not merged
 * onto one balance. Otherwise the note is NOTED and err is clear.
 * merged stays false on every path. Nothing is moved and nothing is
 * broadcast. No hostnames or IPs are used.
 */
SwarmMeshPoolsResult SwarmNoteMeshPools(const SwarmMeshPools& note, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_MESHPOOL_H
