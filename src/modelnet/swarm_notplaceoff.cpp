// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notplaceoff.h>

namespace modelnet {

SwarmNotPlaceOffResult SwarmNoteNotPlaceOff(const SwarmNotPlaceOff& note, std::string& err)
{
    SwarmNotPlaceOffResult result;
    result.published = false;
    result.delta = 0;
    result.bytes_moved = false;
    if (note.run_id.empty()) {
        result.code = "RUN";
        result.published = false;
        result.delta = 0;
        result.bytes_moved = false;
        err = "RUN";
        return result;
    }
    // A comparison with workflow-aware placement disabled has not been measured.
    if (note.want_publish) {
        result.code = "UNMEASURED";
        result.published = false;
        result.delta = 0;
        result.bytes_moved = false;
        err = "UNMEASURED";
        return result;
    }
    result.code = "NOTED";
    result.published = false;
    result.delta = 0;
    result.bytes_moved = false;
    err.clear();
    return result;
}

} // namespace modelnet
