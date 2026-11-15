// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_NOTNOGOVZERO_H
#define BTX_MODELNET_SWARM_NOTNOGOVZERO_H

#include <string>

namespace modelnet {

/**
 * A local note about one node. idle_off records an idle-off drain.
 * want_run asks this note to run workers.
 *
 * The governor drains workers to zero on idle-off. running stays false
 * and workers stays 0 on every path.
 */
struct SwarmNotNoGovZero {
    std::string node_id;
    bool idle_off{false};
    bool want_run{false};
};

/**
 * Outcome of noting a governor drain. running stays false and workers
 * stays 0 on every path. The governor drains workers to zero on idle-off.
 */
struct SwarmNotNoGovZeroResult {
    std::string code;
    bool running{false};
    int workers{0};
};

/**
 * Note a governor drain without starting workers.
 * Order, first match wins: an empty node_id is NODE. If idle_off is
 * true, the note is ZERO even when want_run is false. want_run is HELD.
 * Otherwise the note is NOTED and err is cleared. running stays false
 * and workers stays 0 on every path. The governor drains workers to
 * zero on idle-off.
 */
SwarmNotNoGovZeroResult SwarmNoteNotNoGovZero(const SwarmNotNoGovZero& note, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_NOTNOGOVZERO_H
