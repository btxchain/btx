// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_NOTNOGRADSYNC2_H
#define BTX_MODELNET_SWARM_NOTNOGRADSYNC2_H

#include <string>

namespace modelnet {

/**
 * A local note about one run. want_sync asks this note to run gradient sync.
 *
 * A gradient-sync request does not run.
 * synced and bytes_moved stay false on every path.
 */
struct SwarmNotNoGradSync2 {
    std::string run_id;
    bool want_sync{false};
};

/**
 * Outcome of noting a gradient-sync request. synced and bytes_moved stay
 * false on every path: a gradient-sync request does not run.
 */
struct SwarmNotNoGradSync2Result {
    std::string code;
    bool synced{false};
    bool bytes_moved{false};
};

/**
 * Note a gradient-sync request without running it.
 * Order, first match wins: an empty run_id is RUN.
 * want_sync is NOT_RUN.
 * Otherwise the note is NOTED and err is cleared.
 * synced and bytes_moved stay false on every path.
 * A gradient-sync request does not run.
 */
SwarmNotNoGradSync2Result SwarmNoteNotNoGradSync2(const SwarmNotNoGradSync2& note, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_NOTNOGRADSYNC2_H
