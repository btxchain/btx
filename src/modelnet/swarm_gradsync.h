// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_GRADSYNC_H
#define BTX_MODELNET_SWARM_GRADSYNC_H

#include <cstdint>
#include <string>

namespace modelnet {

/**
 * A gradient sync request is held. update_id names the update. want_sync
 * asks this note to sync.
 *
 * A gradient sync request is held and moves no bytes.
 * synced stays false and bytes_moved stays 0 on every path.
 */
struct SwarmGradSync {
    std::string update_id;
    bool want_sync{false};
};

/**
 * Outcome of noting a held gradient sync request. synced stays false and
 * bytes_moved stays 0 on every path.
 */
struct SwarmGradSyncResult {
    std::string code;
    bool synced{false};
    int64_t bytes_moved{0};
};

/**
 * Note a held gradient sync request. It syncs nothing and moves no bytes.
 * Order, first match wins: an empty update_id is UPDATE.
 * want_sync true is HELD.
 * Otherwise the code is NOTED and err is cleared.
 * synced stays false and bytes_moved stays 0 on every path.
 * A gradient sync request is held and moves no bytes.
 */
SwarmGradSyncResult SwarmNoteGradSync(const SwarmGradSync& update, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_GRADSYNC_H
