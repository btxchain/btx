// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_learnerheld.h>

#include <string>

namespace modelnet {

SwarmLearnerHeldResult SwarmNoteLearnerHeld(const SwarmLearnerHeld& job, std::string& err)
{
    SwarmLearnerHeldResult result;
    result.running = false;
    result.training = false;
    // A learner run request is held and does not train.
    if (job.job_id.empty()) {
        result.code = "JOB";
        result.running = false;
        result.training = false;
        err = "JOB";
        return result;
    }
    if (job.want_run) {
        result.code = "HELD";
        result.running = false;
        result.training = false;
        err = "HELD";
        return result;
    }
    result.code = "NOTED";
    result.running = false;
    result.training = false;
    err.clear();
    return result;
}

} // namespace modelnet
