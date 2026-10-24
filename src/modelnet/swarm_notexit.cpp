// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notexit.h>

namespace modelnet {

SwarmNotExitResult SwarmNoteNotExit(const SwarmNotExit& note, std::string& err)
{
    SwarmNotExitResult result;
    result.measured = false;
    result.broadcast = false;
    if (note.batch_id.empty()) {
        result.code = "BATCH";
        result.measured = false;
        result.broadcast = false;
        err = "BATCH";
        return result;
    }
    // A mass channel exit during a reorganization has not been measured.
    if (note.want_measure) {
        result.code = "MEASURE_REFUSED";
        result.measured = false;
        result.broadcast = false;
        err = "MEASURE_REFUSED";
        return result;
    }
    result.code = "NOTED";
    result.measured = false;
    result.broadcast = false;
    err.clear();
    return result;
}

} // namespace modelnet
