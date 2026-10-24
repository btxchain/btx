// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_NOTNOTHERMAL2_H
#define BTX_MODELNET_SWARM_NOTNOTHERMAL2_H

#include <cstdint>
#include <string>

namespace modelnet {

/**
 * A local note about one node. node_id names the node. thermal records
 * a thermal drain. want_run asks this note to run workers.
 *
 * The governor drains workers to zero on thermal. running stays false
 * and workers stays 0 on every path.
 */
struct SwarmNotNoThermal2 {
    std::string node_id;
    bool thermal{false};
    bool want_run{false};
};

/**
 * Outcome of noting a thermal drain. running stays false and workers
 * stays 0 on every path. The governor drains workers to zero on thermal.
 */
struct SwarmNotNoThermal2Result {
    std::string code;
    bool running{false};
    int64_t workers{0};
};

/**
 * Note a thermal drain without starting workers.
 * Order, first match wins: an empty node_id is NODE. thermal true is
 * DRAINED, even when want_run is false. want_run is HELD. Otherwise
 * the note is NOTED and err is cleared.
 * running stays false and workers stays 0 on every path.
 * The governor drains workers to zero on thermal.
 */
SwarmNotNoThermal2Result SwarmNoteNotNoThermal2(const SwarmNotNoThermal2& note, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_NOTNOTHERMAL2_H
