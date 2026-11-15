// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnofsdp.h>

#include <string>

namespace modelnet {

SwarmNotNoFsdpResult SwarmNoteNotNoFsdp(const SwarmNotNoFsdp& note, std::string& err)
{
    SwarmNotNoFsdpResult result;
    result.distributed = false;
    result.synced = false;
    // One local step is not FSDP.
    if (note.step_id.empty()) {
        result.code = "STEP";
        result.distributed = false;
        result.synced = false;
        err = "STEP";
        return result;
    }
    if (note.want_distributed) {
        result.code = "NOT_DISTRIBUTED";
        result.distributed = false;
        result.synced = false;
        err = "NOT_DISTRIBUTED";
        return result;
    }
    result.code = "NOTED";
    result.distributed = false;
    result.synced = false;
    err.clear();
    return result;
}

} // namespace modelnet
