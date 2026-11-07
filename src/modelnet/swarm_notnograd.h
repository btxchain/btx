// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_NOTNOGRAD_H
#define BTX_MODELNET_SWARM_NOTNOGRAD_H

#include <string>

namespace modelnet {

/**
 * A local note about one step. want_sync asks this note to run gradient sync.
 *
 * Gradient sync has not run. This note moves no bytes. synced and bytes_moved
 * stay false on every path.
 */
struct SwarmNotNoGrad {
    std::string step_id;
    bool want_sync{false};
};

/**
 * Outcome of noting a gradient-sync request. synced and bytes_moved stay
 * false on every path: gradient sync has not run, and this note moves no bytes.
 */
struct SwarmNotNoGradResult {
    std::string code;
    bool synced{false};
    bool bytes_moved{false};
};

/**
 * Note a gradient-sync request without running gradient sync or moving bytes.
 * Order, first match wins: an empty step_id is STEP.
 * want_sync is NOT_SYNCED.
 * Otherwise the note is NOTED and err is clear.
 * synced and bytes_moved stay false on every path.
 */
SwarmNotNoGradResult SwarmNoteNotNoGrad(const SwarmNotNoGrad& note, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_NOTNOGRAD_H
