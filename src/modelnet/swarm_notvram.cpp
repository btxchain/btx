// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notvram.h>

namespace modelnet {

SwarmNotVramResult SwarmNoteNotVram(const SwarmNotVram& note, std::string& err)
{
    // No GPU query. Do not treat a zero byte count as a measurement.
    SwarmNotVramResult out;
    if (note.job_id.empty()) {
        out.code = "JOB";
        out.published = false;
        out.vram_bytes = 0;
        err = "JOB";
        return out;
    }
    if (note.want_publish) {
        out.code = "UNMEASURED";
        out.published = false;
        out.vram_bytes = 0;
        err = "UNMEASURED";
        return out;
    }
    out.code = "NOTED";
    out.published = false;
    out.vram_bytes = 0;
    err.clear();
    return out;
}

} // namespace modelnet
