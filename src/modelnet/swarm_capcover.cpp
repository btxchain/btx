// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_capcover.h>

namespace modelnet {

SwarmCapCoverResult SwarmNoteCapability(const SwarmCapCover& cap, std::string& err)
{
    // An uncovered capability acts on nothing.
    if (cap.capability_id.empty()) {
        err = "CAPABILITY";
        return SwarmCapCoverResult{"CAPABILITY", false};
    }
    if (!cap.covered) {
        err = "NOT_ACTED";
        return SwarmCapCoverResult{"NOT_ACTED", false};
    }
    if (cap.want_act) {
        err = "HELD";
        return SwarmCapCoverResult{"HELD", false};
    }
    err.clear();
    return SwarmCapCoverResult{"NOTED", false};
}

} // namespace modelnet
