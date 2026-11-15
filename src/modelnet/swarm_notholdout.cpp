// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notholdout.h>

#include <string>

namespace modelnet {

SwarmNotHoldoutResult SwarmNoteNotHoldout(const SwarmNotHoldout& note, std::string& err)
{
    SwarmNotHoldoutResult result;
    result.scored = false;
    // Holdout rotation does not score a loaded model.
    if (note.model_id.empty()) {
        result.code = "MODEL";
        result.scored = false;
        err = "MODEL";
        return result;
    }
    if (note.want_score) {
        result.code = "NOT_SCORED";
        result.scored = false;
        err = "NOT_SCORED";
        return result;
    }
    result.code = "NOTED";
    result.scored = false;
    err.clear();
    return result;
}

} // namespace modelnet
