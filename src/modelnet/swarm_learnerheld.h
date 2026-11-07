// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_LEARNERHELD_H
#define BTX_MODELNET_SWARM_LEARNERHELD_H

#include <string>

namespace modelnet {

/**
 * A learner run request is held. job_id names the job. want_run asks this
 * note to run.
 *
 * A learner run request is held and does not train.
 * running stays false and training stays false on every path.
 */
struct SwarmLearnerHeld {
    std::string job_id;
    bool want_run{false};
};

/**
 * Outcome of noting a held learner run request. running stays false and
 * training stays false on every path.
 */
struct SwarmLearnerHeldResult {
    std::string code;
    bool running{false};
    bool training{false};
};

/**
 * Note a held learner run request. It does not run and does not train.
 * Order, first match wins: an empty job_id is JOB.
 * want_run true is HELD.
 * Otherwise the code is NOTED and err is cleared.
 * running stays false and training stays false on every path.
 * A learner run request is held and does not train.
 */
SwarmLearnerHeldResult SwarmNoteLearnerHeld(const SwarmLearnerHeld& job, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_LEARNERHELD_H
