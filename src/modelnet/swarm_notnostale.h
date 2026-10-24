// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_NOTNOSTALE_H
#define BTX_MODELNET_SWARM_NOTNOSTALE_H

#include <string>

namespace modelnet {

/**
 * A local note about one leader. want_commit asks this note to commit
 * that leader.
 *
 * A stale leader does not commit. committed and broadcast stay false
 * on every path.
 */
struct SwarmNotNoStale {
    std::string leader_id;
    bool stale{false};
    bool want_commit{false};
};

/**
 * Outcome of noting a leader. committed and broadcast stay false on
 * every path: a stale leader does not commit.
 */
struct SwarmNotNoStaleResult {
    std::string code;
    bool committed{false};
    bool broadcast{false};
};

/**
 * Note a leader without committing it. Order, first match wins: an empty
 * leader_id is LEADER. stale is STALE even when want_commit is false.
 * want_commit is STALE. Otherwise the note is NOTED and err is clear.
 * committed and broadcast stay false on every path. A stale leader does
 * not commit.
 */
SwarmNotNoStaleResult SwarmNoteNotNoStale(const SwarmNotNoStale& note, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_NOTNOSTALE_H
