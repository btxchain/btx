// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_NOTGRAD_H
#define BTX_MODELNET_SWARM_NOTGRAD_H

#include <string>

namespace modelnet {

/**
 * A local note about one job. want_sync asks this note to run gradient sync.
 *
 * Gradient sync has not run. synced stays false on every path.
 */
struct SwarmNotGrad {
    std::string job_id;
    bool want_sync{false};
};

/**
 * Outcome of noting a gradient-sync request. synced stays false on every path:
 * gradient sync has not run.
 */
struct SwarmNotGradResult {
    std::string code;
    bool synced{false};
};

/**
 * Note a gradient-sync request without running gradient sync.
 * Order, first match wins: an empty job_id is JOB.
 * want_sync is NOT_SYNCED.
 * Otherwise the note is NOTED and err is clear.
 * synced stays false on every path.
 */
SwarmNotGradResult SwarmNoteNotGrad(const SwarmNotGrad& note, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_NOTGRAD_H
