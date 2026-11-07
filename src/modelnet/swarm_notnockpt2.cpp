// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnockpt2.h>

namespace modelnet {

SwarmNotNoCkpt2Result SwarmNoteNotNoCkpt2(const SwarmNotNoCkpt2& note, std::string& err)
{
    SwarmNotNoCkpt2Result result;
    result.saved = false;
    result.bytes_moved = false;
    if (note.run_id.empty()) {
        result.code = "RUN";
        err = "RUN";
        return result;
    }
    if (note.want_save) {
        result.code = "NOT_SAVED";
        err = "NOT_SAVED";
        return result;
    }
    result.code = "NOTED";
    err.clear();
    return result;
}

} // namespace modelnet
