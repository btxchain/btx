// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnofsdprun.h>

#include <string>

namespace modelnet {

SwarmNotNoFsdpRunResult SwarmNoteNotNoFsdpRun(const SwarmNotNoFsdpRun& note, std::string& err)
{
    SwarmNotNoFsdpRunResult result;
    result.ran = false;
    result.gpu = false;
    // An FSDP request does not run and does not mark a GPU pass.
    if (note.run_id.empty()) {
        result.code = "RUN";
        result.ran = false;
        result.gpu = false;
        err = "RUN";
        return result;
    }
    if (note.want_run) {
        result.code = "NOT_RUN";
        result.ran = false;
        result.gpu = false;
        err = "NOT_RUN";
        return result;
    }
    result.code = "NOTED";
    result.ran = false;
    result.gpu = false;
    err.clear();
    return result;
}

} // namespace modelnet
