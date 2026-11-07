// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_METER0_H
#define BTX_MODELNET_SWARM_METER0_H

#include <cstdint>
#include <string>

namespace modelnet {

/**
 * A local note that a measurement was or was not supplied for one node.
 * This note does not invent electricity, wear, or network meter readings
 * and does not store a reading.
 */
struct SwarmMeter0 {
    std::string node_id;
    bool measurement_supplied{false};
    bool want_invent{false};
};

/**
 * Outcome of noting a meter. electricity_atoms stays 0 and recorded stays
 * false on every path. A supplied measurement is noted and still records
 * zero atoms. This note does not store a reading.
 */
struct SwarmMeter0Result {
    std::string code;
    int64_t electricity_atoms{0};
    bool recorded{false};
};

/**
 * Note a meter without inventing a reading.
 * Order, first match wins: an empty node_id is METER. want_invent is
 * INVENTED even when measurement_supplied is true. A missing measurement
 * is UNMEASURED. Otherwise the note is NOTED and err is clear.
 * electricity_atoms stays 0 and recorded stays false on every path.
 * This note does not store a reading.
 */
SwarmMeter0Result SwarmNoteMeter0(const SwarmMeter0& note, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_METER0_H
