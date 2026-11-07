// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnockpt.h>

namespace modelnet {

SwarmNotNoCkptResult SwarmNoteNotNoCkpt(const SwarmNotNoCkpt& note, std::string& err)
{
    SwarmNotNoCkptResult result;
    result.saved = false;
    result.distributed = false;
    if (note.step_id.empty()) {
        result.code = "STEP";
        err = "STEP";
        return result;
    }
    if (note.want_save) {
        result.code = "NO_CHECKPOINT";
        err = "NO_CHECKPOINT";
        return result;
    }
    result.code = "NOTED";
    err.clear();
    return result;
}

} // namespace modelnet
