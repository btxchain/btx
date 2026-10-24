// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnotwonode.h>

#include <string>

namespace modelnet {

SwarmNotNoTwoNodeResult SwarmNoteNotNoTwoNode(const SwarmNotNoTwoNode& note, std::string& err)
{
    SwarmNotNoTwoNodeResult result;
    result.trained = false;
    result.passed = false;
    // Two-node training is not a pass.
    if (note.job_id.empty()) {
        result.code = "JOB";
        result.trained = false;
        result.passed = false;
        err = "JOB";
        return result;
    }
    if (note.want_train) {
        result.code = "UNQUALIFIED";
        result.trained = false;
        result.passed = false;
        err = "UNQUALIFIED";
        return result;
    }
    result.code = "NOTED";
    result.trained = false;
    result.passed = false;
    err.clear();
    return result;
}

} // namespace modelnet
