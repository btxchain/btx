// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_NOTNOSTALE2_H
#define BTX_MODELNET_SWARM_NOTNOSTALE2_H

#include <string>

namespace modelnet {

/**
 * A local note about one island. want_admit asks this note to admit
 * that island.
 *
 * A stale island update is not admitted. admitted and bytes_moved stay
 * false on every path.
 */
struct SwarmNotNoStale2 {
    std::string island_id;
    bool stale{false};
    bool want_admit{false};
};

/**
 * Outcome of noting an island. admitted and bytes_moved stay false on
 * every path: a stale island update is not admitted.
 */
struct SwarmNotNoStale2Result {
    std::string code;
    bool admitted{false};
    bool bytes_moved{false};
};

/**
 * Note an island without admitting it. Order, first match wins: an empty
 * island_id is ISLAND. stale is NOT_ADMITTED even when want_admit is false.
 * want_admit is HELD. Otherwise the note is NOTED and err is cleared.
 * admitted and bytes_moved stay false on every path. A stale island update
 * is not admitted.
 */
SwarmNotNoStale2Result SwarmNoteNotNoStale2(const SwarmNotNoStale2& note, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_NOTNOSTALE2_H
