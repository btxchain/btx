// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notrollout.h>

namespace modelnet {

SwarmNotRolloutResult SwarmNoteNotRollout(const SwarmNotRollout& note, std::string& err)
{
    SwarmNotRolloutResult result;
    if (note.agent_id.empty()) {
        result.code = "AGENT";
        result.generated = false;
        result.recorded = false;
        err = "AGENT";
        return result;
    }
    if (note.want_generate) {
        result.code = "NOT_RECORDED";
        result.generated = false;
        result.recorded = false;
        err = "NOT_RECORDED";
        return result;
    }
    result.code = "NOTED";
    result.generated = false;
    result.recorded = false;
    err.clear();
    return result;
}

} // namespace modelnet
