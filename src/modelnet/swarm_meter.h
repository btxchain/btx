// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_METER_H
#define BTX_MODELNET_SWARM_METER_H

#include <cstdint>
#include <string>

namespace modelnet {

/**
 * A resource meter reading. This function does not read electricity, wear,
 * or network hardware. A caller-supplied number is not a measurement.
 */
struct SwarmMeterReading {
    bool measured{false};
    int64_t watts{0};
    int64_t wear{0};
    int64_t network_atoms{0};
    std::string code;
};

/**
 * Always METER_ABSENT. measured stays false and the numeric fields stay 0.
 * caller_supplied_watts is ignored. This is not a rank input.
 */
SwarmMeterReading SwarmReadResourceMeter(int64_t caller_supplied_watts, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_METER_H
