// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notcanary.h>

#include <string>

namespace modelnet {

SwarmNotCanaryResult SwarmNoteNotCanary(const SwarmNotCanary& note, std::string& err)
{
    SwarmNotCanaryResult result;
    result.rolled = false;
    // A regression attachment is not a live canary rollout.
    if (note.candidate_id.empty()) {
        result.code = "CANDIDATE";
        result.rolled = false;
        err = "CANDIDATE";
        return result;
    }
    if (note.want_roll) {
        result.code = "NOT_CANARY";
        result.rolled = false;
        err = "NOT_CANARY";
        return result;
    }
    result.code = "NOTED";
    result.rolled = false;
    err.clear();
    return result;
}

} // namespace modelnet
