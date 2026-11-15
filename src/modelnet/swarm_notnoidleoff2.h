// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_NOTNOIDLEOFF2_H
#define BTX_MODELNET_SWARM_NOTNOIDLEOFF2_H

#include <cstdint>
#include <string>

namespace modelnet {

/**
 * A local note about one node. idle_off records an idle-off drain.
 * want_run asks this note to run workers.
 *
 * The governor drains workers to zero when idle is off. running stays false
 * and workers stays 0 on every path.
 */
struct SwarmNotNoIdleOff2 {
    std::string node_id;
    bool idle_off{false};
    bool want_run{false};
};

/**
 * Outcome of noting a governor drain. running stays false and workers
 * stays 0 on every path. The governor drains workers to zero when idle is off.
 */
struct SwarmNotNoIdleOff2Result {
    std::string code;
    bool running{false};
    int64_t workers{0};
};

/**
 * Note a governor drain without starting workers.
 * Order, first match wins: an empty node_id is NODE. If idle_off is
 * true, the note is DRAINED even when want_run is false. want_run is HELD.
 * Otherwise the note is NOTED and err is cleared. running stays false
 * and workers stays 0 on every path. The governor drains workers to
 * zero when idle is off.
 */
SwarmNotNoIdleOff2Result SwarmNoteNotNoIdleOff2(const SwarmNotNoIdleOff2& note, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_NOTNOIDLEOFF2_H
