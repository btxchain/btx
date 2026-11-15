// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_NOTNOGOVTHERM_H
#define BTX_MODELNET_SWARM_NOTNOGOVTHERM_H

#include <string>

namespace modelnet {

/**
 * A local note about one node under thermal drain. thermal records that
 * the governor should drain workers. want_run asks this note to run workers.
 *
 * The governor drains workers to zero on thermal. running stays false
 * and workers stays 0 on every path.
 */
struct SwarmNotNoGovTherm {
    std::string node_id;
    bool thermal{false};
    bool want_run{false};
};

/**
 * Outcome of noting a thermal drain. running stays false and workers
 * stays 0 on every path. The governor drains workers to zero on thermal.
 */
struct SwarmNotNoGovThermResult {
    std::string code;
    bool running{false};
    int workers{0};
};

/**
 * Note a thermal drain without starting workers.
 * Order, first match wins: an empty node_id is NODE. If thermal is
 * true, the note is ZERO even when want_run is false. want_run is
 * HELD. Otherwise the note is NOTED and err is cleared. running stays
 * false and workers stays 0 on every path. The governor drains workers
 * to zero on thermal.
 */
SwarmNotNoGovThermResult SwarmNoteNotNoGovTherm(const SwarmNotNoGovTherm& note, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_NOTNOGOVTHERM_H
