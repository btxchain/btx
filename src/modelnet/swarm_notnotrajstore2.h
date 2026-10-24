// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_NOTNOTRAJSTORE2_H
#define BTX_MODELNET_SWARM_NOTNOTRAJSTORE2_H

#include <string>

namespace modelnet {

/**
 * A local note about one trajectory store. want_store asks this note
 * to store it.
 *
 * A trajectory store has not run and this note stores nothing, so
 * stored and bytes_moved stay false on every path.
 */
struct SwarmNotNoTrajStore2 {
    std::string store_id;
    bool want_store{false};
};

/**
 * Outcome of noting a trajectory store. stored and bytes_moved stay
 * false on every path. A trajectory store has not run and this note
 * stores nothing.
 */
struct SwarmNotNoTrajStore2Result {
    std::string code;
    bool stored{false};
    bool bytes_moved{false};
};

/**
 * Note a trajectory store without storing.
 * Order, first match wins: an empty store_id is STORE.
 * want_store is HELD. Otherwise the note is NOTED and err is cleared.
 * stored and bytes_moved stay false on every path. A trajectory store
 * has not run and this note stores nothing.
 */
SwarmNotNoTrajStore2Result SwarmNoteNotNoTrajStore2(const SwarmNotNoTrajStore2& note, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_NOTNOTRAJSTORE2_H
