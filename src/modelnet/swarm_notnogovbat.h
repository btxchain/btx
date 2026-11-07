// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_NOTNOGOVBAT_H
#define BTX_MODELNET_SWARM_NOTNOGOVBAT_H

#include <string>

namespace modelnet {

/**
 * A local note about one node on battery. battery records that the
 * governor should drain workers. want_run asks this note to run workers.
 *
 * The governor drains workers to zero on battery. running stays false
 * and workers stays 0 on every path.
 */
struct SwarmNotNoGovBat {
    std::string node_id;
    bool battery{false};
    bool want_run{false};
};

/**
 * Outcome of noting a battery drain. running stays false and workers
 * stays 0 on every path. The governor drains workers to zero on battery.
 */
struct SwarmNotNoGovBatResult {
    std::string code;
    bool running{false};
    int workers{0};
};

/**
 * Note a battery drain without starting workers.
 * Order, first match wins: an empty node_id is NODE. If battery is
 * true, the note is ZERO even when want_run is false. want_run is
 * HELD. Otherwise the note is NOTED and err is cleared. running stays
 * false and workers stays 0 on every path. The governor drains workers
 * to zero on battery.
 */
SwarmNotNoGovBatResult SwarmNoteNotNoGovBat(const SwarmNotNoGovBat& note, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_NOTNOGOVBAT_H
