// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notuseful.h>

namespace modelnet {

SwarmNotUsefulResult SwarmNoteNotUseful(const SwarmNotUseful& note, std::string& err)
{
    // Publication never happens. gpu_hours stays 0. useful stays false.
    // Nothing here claims a GPU ran.
    SwarmNotUsefulResult out;
    out.published = false;
    out.gpu_hours = 0;
    out.useful = false;

    if (note.task_id.empty()) {
        out.code = "TASK";
        err = "TASK";
        return out;
    }
    if (note.want_publish) {
        out.code = "UNMEASURED";
        err = "UNMEASURED";
        return out;
    }
    out.code = "NOTED";
    err.clear();
    return out;
}

} // namespace modelnet
