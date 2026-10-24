// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnouseful.h>

namespace modelnet {

SwarmNotNoUsefulResult SwarmNoteNotNoUseful(const SwarmNotNoUseful& note, std::string& err)
{
    SwarmNotNoUsefulResult result;
    result.useful = false;
    result.paid = false;
    if (note.task_id.empty()) {
        result.code = "TASK";
        result.useful = false;
        result.paid = false;
        err = "TASK";
        return result;
    }
    // A note does not mark work useful and pays nothing.
    if (note.want_claim) {
        result.code = "NOT_USEFUL";
        result.useful = false;
        result.paid = false;
        err = "NOT_USEFUL";
        return result;
    }
    result.code = "NOTED";
    result.useful = false;
    result.paid = false;
    err.clear();
    return result;
}

} // namespace modelnet
