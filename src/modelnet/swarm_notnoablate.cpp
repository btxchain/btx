// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnoablate.h>

namespace modelnet {

SwarmNotNoAblateResult SwarmNoteNotNoAblate(const SwarmNotNoAblate& note, std::string& err)
{
    // An ablation note does not change weights.
    if (note.run_id.empty()) {
        err = "RUN";
        return SwarmNotNoAblateResult{"RUN", false, false};
    }
    if (note.want_change) {
        err = "NOT_CHANGED";
        return SwarmNotNoAblateResult{"NOT_CHANGED", false, false};
    }
    err.clear();
    return SwarmNotNoAblateResult{"NOTED", false, false};
}

} // namespace modelnet
