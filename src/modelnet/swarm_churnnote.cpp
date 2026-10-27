// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_churnnote.h>

namespace modelnet {

SwarmChurnNoteResult SwarmNoteChurn(const SwarmChurnNote& note, std::string& err)
{
    // A churned peer sends nothing.
    if (note.peer_id.empty()) {
        err = "PEER";
        return SwarmChurnNoteResult{"PEER", false, 0};
    }
    if (note.churned) {
        err = "CHURNED";
        return SwarmChurnNoteResult{"CHURNED", false, 0};
    }
    if (note.want_send) {
        err = "HELD";
        return SwarmChurnNoteResult{"HELD", false, 0};
    }
    err.clear();
    return SwarmChurnNoteResult{"NOTED", false, 0};
}

} // namespace modelnet
