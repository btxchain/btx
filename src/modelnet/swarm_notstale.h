// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_NOTSTALE_H
#define BTX_MODELNET_SWARM_NOTSTALE_H

#include <string>

namespace modelnet {

/**
 * A local note about one epoch. want_commit asks this note to commit that
 * epoch from an old coordinator.
 *
 * An old coordinator with a stale epoch commits nothing. committed stays
 * false on every path.
 */
struct SwarmNotStale {
    std::string epoch_id;
    bool want_commit{false};
};

/**
 * Outcome of noting a stale-epoch request. committed stays false on every
 * path: an old coordinator with a stale epoch commits nothing.
 */
struct SwarmNotStaleResult {
    std::string code;
    bool committed{false};
};

/**
 * Note an epoch without committing it. Order, first match wins: an empty
 * epoch_id is EPOCH. want_commit is STALE. Otherwise the note is NOTED and
 * err is clear. committed stays false on every path.
 */
SwarmNotStaleResult SwarmNoteNotStale(const SwarmNotStale& note, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_NOTSTALE_H
