// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_NOTNCCL_H
#define BTX_MODELNET_SWARM_NOTNCCL_H

#include <string>

namespace modelnet {

/**
 * A local note about one job. want_sync asks this note to synchronize.
 *
 * This note does not start NCCL or move bytes. synced and bytes_moved
 * stay false on every path.
 */
struct SwarmNotNccl {
    std::string job_id;
    bool want_sync{false};
};

/**
 * Outcome of noting a sync request. synced and bytes_moved stay false on
 * every path: this note does not start NCCL or move bytes.
 */
struct SwarmNotNcclResult {
    std::string code;
    bool synced{false};
    bool bytes_moved{false};
};

/**
 * Note a sync request without starting NCCL or moving bytes.
 * Order, first match wins: an empty job_id is JOB. want_sync is
 * ENGINE_ABSENT. Otherwise the note is NOTED and err is clear.
 * synced and bytes_moved stay false on every path.
 */
SwarmNotNcclResult SwarmNoteNotNccl(const SwarmNotNccl& note, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_NOTNCCL_H
