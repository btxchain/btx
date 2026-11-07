// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnocanary.h>

#include <string>

namespace modelnet {

SwarmNotNoCanaryResult SwarmNoteNotNoCanary(const SwarmNotNoCanary& note, std::string& err)
{
    SwarmNotNoCanaryResult result;
    result.ran = false;
    result.regressed = false;
    // A local note does not run a canary.
    if (note.canary_id.empty()) {
        result.code = "CANARY";
        result.ran = false;
        result.regressed = false;
        err = "CANARY";
        return result;
    }
    if (note.want_run) {
        result.code = "NOT_RUN";
        result.ran = false;
        result.regressed = false;
        err = "NOT_RUN";
        return result;
    }
    result.code = "NOTED";
    result.ran = false;
    result.regressed = false;
    err.clear();
    return result;
}

} // namespace modelnet
