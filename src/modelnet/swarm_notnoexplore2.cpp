// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnoexplore2.h>

#include <string>

namespace modelnet {

SwarmNotNoExplore2Result SwarmNoteNotNoExplore2(const SwarmNotNoExplore2& note, std::string& err)
{
    SwarmNotNoExplore2Result result;
    result.assigned = false;
    result.slots = 0;
    // An exploration illustration of 5 slots, 200000 ppm, and 3
    // candidates records 1, 2, 2 and assigns nothing.
    if (note.run_id.empty()) {
        result.code = "RUN";
        result.assigned = false;
        result.slots = 0;
        err = "RUN";
        return result;
    }
    if (note.want_assign) {
        result.code = "NOT_ASSIGNED";
        result.assigned = false;
        result.slots = 0;
        err = "NOT_ASSIGNED";
        return result;
    }
    result.code = "NOTED";
    result.assigned = false;
    result.slots = 0;
    err.clear();
    return result;
}

} // namespace modelnet
