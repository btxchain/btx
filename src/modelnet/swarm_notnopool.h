// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_NOTNOPOOL_H
#define BTX_MODELNET_SWARM_NOTNOPOOL_H

#include <cstdint>
#include <string>

namespace modelnet {

/**
 * A local note about a pool. want_open_mesh asks this note to open a mesh.
 *
 * Many pools stay on one payment mesh, and this note opens no mesh.
 * opened stays false and meshes stays 0 on every path.
 */
struct SwarmNotNoPool {
    std::string pool_id;
    bool want_open_mesh{false};
};

/**
 * Outcome of noting a pool. opened stays false and meshes stays 0 on every
 * path. Many pools stay on one payment mesh, and this note opens no mesh.
 */
struct SwarmNotNoPoolResult {
    std::string code;
    bool opened{false};
    int64_t meshes{0};
};

/**
 * Note a pool without opening a mesh.
 * Order, first match wins: an empty pool_id is POOL. want_open_mesh is
 * ONE_MESH. Otherwise the note is NOTED and err is clear.
 * opened stays false and meshes stays 0 on every path.
 * Many pools stay on one payment mesh, and this note opens no mesh.
 */
SwarmNotNoPoolResult SwarmNoteNotNoPool(const SwarmNotNoPool& note, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_NOTNOPOOL_H
