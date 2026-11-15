// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnomixed.h>

#include <string>

namespace modelnet {

SwarmNotNoMixedResult SwarmNoteNotNoMixed(const SwarmNotNoMixed& note, std::string& err)
{
    SwarmNotNoMixedResult result;
    result.mixed = false;
    result.trained = false;
    // Mixed precision has not run. This note trains nothing.
    if (note.step_id.empty()) {
        result.code = "STEP";
        result.mixed = false;
        result.trained = false;
        err = "STEP";
        return result;
    }
    if (note.want_mixed) {
        result.code = "NOT_RUN";
        result.mixed = false;
        result.trained = false;
        err = "NOT_RUN";
        return result;
    }
    result.code = "NOTED";
    result.mixed = false;
    result.trained = false;
    err.clear();
    return result;
}

} // namespace modelnet
