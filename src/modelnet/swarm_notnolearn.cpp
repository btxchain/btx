// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnolearn.h>

#include <string>

namespace modelnet {

SwarmNotNoLearnResult SwarmNoteNotNoLearn(const SwarmNotNoLearn& note, std::string& err)
{
    SwarmNotNoLearnResult result;
    result.spent = false;
    result.atoms = 0;
    // A learner note spends nothing.
    if (note.learner_id.empty()) {
        result.code = "LEARNER";
        result.spent = false;
        result.atoms = 0;
        err = "LEARNER";
        return result;
    }
    if (note.want_spend) {
        result.code = "HELD";
        result.spent = false;
        result.atoms = 0;
        err = "HELD";
        return result;
    }
    result.code = "NOTED";
    result.spent = false;
    result.atoms = 0;
    err.clear();
    return result;
}

} // namespace modelnet
