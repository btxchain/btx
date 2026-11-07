// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnofsdp2.h>

#include <string>

namespace modelnet {

SwarmNotNoFsdp2Result SwarmNoteNotNoFsdp2(const SwarmNotNoFsdp2& note, std::string& err)
{
    SwarmNotNoFsdp2Result result;
    result.ran = false;
    result.gpu = false;
    // An FSDP request does not run.
    if (note.run_id.empty()) {
        result.code = "RUN";
        result.ran = false;
        result.gpu = false;
        err = "RUN";
        return result;
    }
    if (note.want_fsdp) {
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
