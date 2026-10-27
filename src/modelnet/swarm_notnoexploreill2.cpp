// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnoexploreill2.h>

#include <string>

namespace modelnet {

SwarmNotNoExploreIll2Result SwarmNoteNotNoExploreIll2(const SwarmNotNoExploreIll2& note, std::string& err)
{
    SwarmNotNoExploreIll2Result result;
    result.assigned = false;
    result.slots = 0;
    // An exploration illustration records 1, 2, and 2 and assigns nothing.
    if (note.run_id.empty()) {
        result.code = "RUN";
        result.assigned = false;
        result.slots = 0;
        err = "RUN";
        return result;
    }
    if (note.want_assign) {
        result.code = "HELD";
        result.assigned = false;
        result.slots = 0;
        err = "HELD";
        return result;
    }
    result.code = "NOTED";
    result.assigned = false;
    result.slots = 0;
    err.clear();
    return result;
}

} // namespace modelnet
