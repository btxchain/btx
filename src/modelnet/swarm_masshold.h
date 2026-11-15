// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_MASSHOLD_H
#define BTX_MODELNET_SWARM_MASSHOLD_H

#include <cstdint>
#include <string>

namespace modelnet {

/**
 * A local note about a mass exit. An assumed byte count is not a
 * measured close size. Nothing is broadcast.
 */
struct SwarmMassExitNote {
    int64_t channels{0};
    int64_t assumed_bytes{0};
    bool measured{false};
    bool want_broadcast{false};
};

/**
 * Outcome of noting a mass exit. broadcast and measured_size stay
 * false: nothing is broadcast and an assumed byte count is not a
 * measured close size.
 */
struct SwarmMassExitResult {
    bool broadcast{false};
    bool measured_size{false};
    std::string code;
};

/**
 * Note a mass exit. Order, first match wins: channels < 1 or
 * assumed_bytes < 1 is EXIT. A request that wants broadcast is
 * BROADCAST_FORBIDDEN, even when measured is true. A measured flag
 * is MEASURE_REFUSED. A caller flag is not a measurement. Otherwise
 * the note is ASSUMED and err is cleared. broadcast and measured_size
 * stay false on every path. An assumed byte count is not a measured
 * close size and nothing is broadcast.
 */
SwarmMassExitResult SwarmNoteMassExit(const SwarmMassExitNote& note, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_MASSHOLD_H
