// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_THERMALDRAIN_H
#define BTX_MODELNET_SWARM_THERMALDRAIN_H

#include <cstdint>
#include <string>

namespace modelnet {

/**
 * A thermal-drain record. node_id names the node. thermal is whether a
 * thermal limit is active. want_run asks this record to hold a run request.
 *
 * A thermal limit drains workers to zero. A run request is held.
 */
struct SwarmThermalDrain {
    std::string node_id;
    bool thermal{false};
    bool want_run{false};
};

/**
 * Outcome of noting a thermal drain. workers stays 0 on every path.
 * A thermal limit drains workers to zero.
 */
struct SwarmThermalDrainResult {
    std::string code;
    int64_t workers{0};
};

/**
 * Note a thermal drain. Order, first match wins: an empty node_id is NODE.
 * thermal true is DRAINED even when want_run is false. want_run is HELD.
 * Otherwise the note is NOTED and err is clear. A thermal limit drains
 * workers to zero. workers stays 0 on every path.
 */
SwarmThermalDrainResult SwarmNoteThermalDrain(const SwarmThermalDrain& node, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_THERMALDRAIN_H
