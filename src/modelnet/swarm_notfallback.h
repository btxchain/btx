// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_NOTFALLBACK_H
#define BTX_MODELNET_SWARM_NOTFALLBACK_H

#include <string>

namespace modelnet {

/**
 * A local note about one node. gpu_present records whether a GPU is on the
 * platform. want_observe asks this note to keep the observer. want_train asks
 * this note to advertise training.
 *
 * A missing GPU still keeps the observer. Training is never started here.
 * observer_kept is true on every path except an empty node_id. training stays
 * false on every path.
 */
struct SwarmNotFallback {
    std::string node_id;
    bool gpu_present{false};
    bool want_observe{false};
    bool want_train{false};
};

/**
 * Outcome of noting a fallback claim. observer_kept is true on every path
 * except an empty node_id. training stays false on every path.
 */
struct SwarmNotFallbackResult {
    std::string code;
    bool observer_kept{false};
    bool training{false};
};

/**
 * Note a fallback claim without dropping the observer or starting training.
 * Order, first match wins:
 * 1. An empty node_id is NODE. observer_kept stays false, training stays
 *    false, and err is NODE.
 * 2. want_train is CPU_ONLY. observer_kept is true, training stays false,
 *    and err is CPU_ONLY. A missing GPU still keeps the observer.
 * 3. want_observe is NOTED. observer_kept is true, training stays false,
 *    and err is cleared.
 * 4. Otherwise the note is NOTED. observer_kept is true, training stays
 *    false, and err is cleared.
 * observer_kept is true on every path except an empty node_id. training
 * stays false on every path.
 */
SwarmNotFallbackResult SwarmNoteNotFallback(const SwarmNotFallback& note, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_NOTFALLBACK_H
