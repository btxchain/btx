// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notcrash.h>

namespace modelnet {

SwarmNotCrashResult SwarmNoteNotCrash(const SwarmNotCrash& note, std::string& err)
{
    if (note.node_id.empty()) {
        err = "NODE";
        return SwarmNotCrashResult{"NODE", false, false};
    }
    if (note.want_recover) {
        err = "NOT_SHOWN";
        return SwarmNotCrashResult{"NOT_SHOWN", false, false};
    }
    err.clear();
    return SwarmNotCrashResult{"NOTED", false, false};
}

} // namespace modelnet
