// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnolearner2.h>

#include <string>

namespace modelnet {

SwarmNotNoLearner2Result SwarmNoteNotNoLearner2(const SwarmNotNoLearner2& note, std::string& err)
{
    SwarmNotNoLearner2Result result;
    result.running = false;
    // A learner has not run and this note runs nothing.
    if (note.learner_id.empty()) {
        result.code = "LEARNER";
        result.running = false;
        err = "LEARNER";
        return result;
    }
    if (note.want_run) {
        result.code = "HELD";
        result.running = false;
        err = "HELD";
        return result;
    }
    result.code = "NOTED";
    result.running = false;
    err.clear();
    return result;
}

} // namespace modelnet
