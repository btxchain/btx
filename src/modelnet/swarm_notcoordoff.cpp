// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notcoordoff.h>

namespace modelnet {

SwarmNotCoordOffResult SwarmNoteNotCoordOff(const SwarmNotCoordOff& note, std::string& err)
{
    // A comparison with coordination disabled has not been measured.
    SwarmNotCoordOffResult result;
    if (note.run_id.empty()) {
        result.code = "RUN";
        result.published = false;
        result.delta = 0;
        err = "RUN";
        return result;
    }
    if (note.want_publish) {
        result.code = "UNMEASURED";
        result.published = false;
        result.delta = 0;
        err = "UNMEASURED";
        return result;
    }
    result.code = "NOTED";
    result.published = false;
    result.delta = 0;
    err.clear();
    return result;
}

} // namespace modelnet
