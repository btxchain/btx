// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_TRAJSTORE_H
#define BTX_MODELNET_SWARM_TRAJSTORE_H

#include <cstdint>
#include <string>

namespace modelnet {

/**
 * A local note about one trajectory store request. want_store asks this
 * note to store it.
 *
 * A trajectory store request is held and stores nothing, so stored stays
 * false and bytes_moved stays 0 on every path.
 */
struct SwarmTrajStore {
    std::string item_id;
    bool want_store{false};
};

/**
 * Outcome of noting a trajectory store request. stored stays false and
 * bytes_moved stays 0 on every path. A trajectory store request is held
 * and stores nothing.
 */
struct SwarmTrajStoreResult {
    std::string code;
    bool stored{false};
    int64_t bytes_moved{0};
};

/**
 * Note a trajectory store request without storing.
 * Order, first match wins: an empty item_id is ITEM. want_store is HELD.
 * Otherwise the note is NOTED and err is cleared.
 * stored stays false and bytes_moved stays 0 on every path.
 * A trajectory store request is held and stores nothing.
 */
SwarmTrajStoreResult SwarmNoteTrajStore(const SwarmTrajStore& item, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_TRAJSTORE_H
