// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnomassexit.h>

#include <cstdint>
#include <string>

namespace modelnet {

SwarmNotNoMassExitResult SwarmNoteNotNoMassExit(const SwarmNotNoMassExit& note, std::string& err)
{
    SwarmNotNoMassExitResult result;
    result.measured = false;
    result.bytes = 0;
    // An assumed mass-exit size, including 8000 bytes, is not a measurement and moves no bytes.
    if (note.island_id.empty()) {
        result.code = "ISLAND";
        result.measured = false;
        result.bytes = 0;
        err = "ISLAND";
        return result;
    }
    if (note.assumed_size) {
        result.code = "UNMEASURED";
        result.measured = false;
        result.bytes = 0;
        err = "UNMEASURED";
        return result;
    }
    if (note.want_measure) {
        result.code = "UNMEASURED";
        result.measured = false;
        result.bytes = 0;
        err = "UNMEASURED";
        return result;
    }
    result.code = "NOTED";
    result.measured = false;
    result.bytes = 0;
    err.clear();
    return result;
}

} // namespace modelnet
