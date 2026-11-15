// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_NOTNOGRADSYNC_H
#define BTX_MODELNET_SWARM_NOTNOGRADSYNC_H

#include <string>

namespace modelnet {

/**
 * A local note about one run. want_sync asks this note to run gradient sync.
 *
 * A gradient-sync request does not run and does not mark a GPU pass.
 * synced and gpu stay false on every path.
 */
struct SwarmNotNoGradSync {
    std::string run_id;
    bool want_sync{false};
};

/**
 * Outcome of noting a gradient-sync request. synced and gpu stay false on
 * every path: a gradient-sync request does not run and does not mark a GPU
 * pass.
 */
struct SwarmNotNoGradSyncResult {
    std::string code;
    bool synced{false};
    bool gpu{false};
};

/**
 * Note a gradient-sync request without running it and without marking a GPU pass.
 * Order, first match wins: an empty run_id is RUN.
 * want_sync is NOT_RUN.
 * Otherwise the note is NOTED and err is cleared.
 * synced and gpu stay false on every path.
 * A gradient-sync request does not run and does not mark a GPU pass.
 */
SwarmNotNoGradSyncResult SwarmNoteNotNoGradSync(const SwarmNotNoGradSync& note, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_NOTNOGRADSYNC_H
