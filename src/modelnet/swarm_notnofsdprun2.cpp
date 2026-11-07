// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnofsdprun2.h>

#include <string>

namespace modelnet {

SwarmNotNoFsdpRun2Result SwarmNoteNotNoFsdpRun2(const SwarmNotNoFsdpRun2& note, std::string& err)
{
    SwarmNotNoFsdpRun2Result result;
    result.running = false;
    // FSDP has not run and this note runs nothing.
    if (note.run_id.empty()) {
        result.code = "RUN";
        result.running = false;
        err = "RUN";
        return result;
    }
    if (note.want_run) {
        result.code = "HELD";
        result.running = false;
        err = "HELD";
        return result;
    }
    result.code = "NOTED";
    result.running = false;
    err.clear();
    return result;
}

} // namespace modelnet
