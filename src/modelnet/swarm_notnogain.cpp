// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnogain.h>

namespace modelnet {

SwarmNotNoGainResult SwarmNoteNotNoGain(const SwarmNotNoGain& note, std::string& err)
{
    SwarmNotNoGainResult result;
    result.gained = false;
    result.evaluated = false;
    if (note.step_id.empty()) {
        result.code = "STEP";
        result.gained = false;
        result.evaluated = false;
        err = "STEP";
        return result;
    }
    // One training step is not a quality gain.
    if (note.want_claim) {
        result.code = "NOT_EVALUATED";
        result.gained = false;
        result.evaluated = false;
        err = "NOT_EVALUATED";
        return result;
    }
    result.code = "NOTED";
    result.gained = false;
    result.evaluated = false;
    err.clear();
    return result;
}

} // namespace modelnet
