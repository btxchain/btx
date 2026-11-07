// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notsequence.h>

#include <string>

namespace modelnet {

SwarmNotSequenceResult SwarmNoteNotSequence(const SwarmNotSequence& note, std::string& err)
{
    SwarmNotSequenceResult result;
    result.stepped = false;
    result.applied_steps = 0;
    // A clearing close uses one sequence step. This note does not take it.
    if (note.channel_id.empty()) {
        result.code = "CHANNEL";
        result.stepped = false;
        result.applied_steps = 0;
        err = "CHANNEL";
        return result;
    }
    if (note.step_count != 1) {
        result.code = "ONE_STEP";
        result.stepped = false;
        result.applied_steps = 0;
        err = "ONE_STEP";
        return result;
    }
    if (note.want_step) {
        result.code = "ONE_STEP";
        result.stepped = false;
        result.applied_steps = 0;
        err = "ONE_STEP";
        return result;
    }
    result.code = "NOTED";
    result.stepped = false;
    result.applied_steps = 0;
    err.clear();
    return result;
}

} // namespace modelnet
