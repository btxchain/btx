// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_masshold.h>

#include <cstdint>

namespace modelnet {

SwarmMassExitResult SwarmNoteMassExit(const SwarmMassExitNote& note, std::string& err)
{
    SwarmMassExitResult result;
    result.broadcast = false;
    result.measured_size = false;
    if (note.channels < 1 || note.assumed_bytes < 1) {
        result.code = "EXIT";
        err = "EXIT";
        return result;
    }
    if (note.want_broadcast) {
        result.broadcast = false;
        result.measured_size = false;
        result.code = "BROADCAST_FORBIDDEN";
        err = "BROADCAST_FORBIDDEN";
        return result;
    }
    if (note.measured) {
        result.broadcast = false;
        result.measured_size = false;
        result.code = "MEASURE_REFUSED";
        err = "MEASURE_REFUSED";
        return result;
    }
    result.broadcast = false;
    result.measured_size = false;
    result.code = "ASSUMED";
    err.clear();
    return result;
}

} // namespace modelnet
