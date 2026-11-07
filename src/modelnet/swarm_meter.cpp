// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_meter.h>

namespace modelnet {

SwarmMeterReading SwarmReadResourceMeter(int64_t /*caller_supplied_watts*/, std::string& err)
{
    SwarmMeterReading reading;
    reading.measured = false;
    reading.watts = 0;
    reading.wear = 0;
    reading.network_atoms = 0;
    reading.code = "METER_ABSENT";
    err = "METER_ABSENT";
    return reading;
}

} // namespace modelnet
