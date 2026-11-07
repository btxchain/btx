// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_NOTNODRAIN_H
#define BTX_MODELNET_SWARM_NOTNODRAIN_H

#include <cstdint>
#include <string>

namespace modelnet {

/**
 * A local note about one node. idle_off, battery, thermal, and metered
 * record drain conditions. want_run asks this note to run workers.
 *
 * A governor drain starts no workers. running stays false and workers
 * stays 0 on every path.
 */
struct SwarmNotNoDrain {
    std::string node_id;
    bool idle_off{false};
    bool battery{false};
    bool thermal{false};
    bool metered{false};
    bool want_run{false};
};

/**
 * Outcome of noting a governor drain. running stays false and workers
 * stays 0 on every path. A governor drain starts no workers.
 */
struct SwarmNotNoDrainResult {
    std::string code;
    bool running{false};
    int64_t workers{0};
};

/**
 * Note a governor drain without starting workers.
 * Order, first match wins:
 * 1. An empty node_id is NODE. running stays false, workers stays 0,
 *    and err is NODE.
 * 2. idle_off, battery, thermal, or metered is DRAINED, even when
 *    want_run is false. running stays false, workers stays 0, and
 *    err is DRAINED.
 * 3. want_run is NOT_RUN. running stays false, workers stays 0, and
 *    err is NOT_RUN.
 * 4. Otherwise the note is NOTED. running stays false, workers stays
 *    0, and err is cleared.
 * A governor drain starts no workers.
 */
SwarmNotNoDrainResult SwarmNoteNotNoDrain(const SwarmNotNoDrain& note, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_NOTNODRAIN_H
