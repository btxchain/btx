// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notgpuhours.h>

namespace modelnet {

SwarmNotGpuHoursResult SwarmNoteNotGpuHours(const SwarmNotGpuHours& note, std::string& err)
{
    // Publication never happens. gpu_hours stays 0. Nothing here claims a GPU ran.
    SwarmNotGpuHoursResult out;
    out.published = false;
    out.gpu_hours = 0;

    if (note.job_id.empty()) {
        out.code = "JOB";
        err = "JOB";
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
