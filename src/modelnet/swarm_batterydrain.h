// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_BATTERYDRAIN_H
#define BTX_MODELNET_SWARM_BATTERYDRAIN_H

#include <cstdint>
#include <string>

namespace modelnet {

/**
 * A battery-drain record. node_id names the node. battery is whether the
 * host is on battery. want_run asks this record to hold a run request.
 *
 * Battery drains workers to zero. A run request is held.
 */
struct SwarmBatteryDrain {
    std::string node_id;
    bool battery{false};
    bool want_run{false};
};

/**
 * Outcome of noting a battery drain. workers stays 0 on every path.
 * Battery drains workers to zero.
 */
struct SwarmBatteryDrainResult {
    std::string code;
    int64_t workers{0};
};

/**
 * Note a battery drain. Order, first match wins: an empty node_id is NODE.
 * battery true is DRAINED even when want_run is false. want_run is HELD.
 * Otherwise the note is NOTED and err is clear. Battery drains workers to
 * zero. workers stays 0 on every path.
 */
SwarmBatteryDrainResult SwarmNoteBatteryDrain(const SwarmBatteryDrain& node, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_BATTERYDRAIN_H
