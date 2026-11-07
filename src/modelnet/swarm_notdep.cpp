// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notdep.h>

namespace modelnet {

SwarmNotDepResult SwarmNoteNotDep(const SwarmNotDep& note, std::string& err)
{
    // This note does not probe the filesystem.
    if (note.dep_id.empty()) {
        err = "DEP";
        return SwarmNotDepResult{"DEP", false, false};
    }
    if (note.want_detect) {
        err = "NOT_DETECTED";
        return SwarmNotDepResult{"NOT_DETECTED", false, false};
    }
    err.clear();
    return SwarmNotDepResult{"NOTED", false, false};
}

} // namespace modelnet
