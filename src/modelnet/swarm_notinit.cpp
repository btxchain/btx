// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notinit.h>

namespace modelnet {

SwarmNotInitResult SwarmNoteNotInit(const SwarmNotInit& note, std::string& err)
{
    // This note does not start or stop a process.
    if (note.node_id.empty()) {
        err = "NODE";
        return SwarmNotInitResult{"NODE", false, false};
    }
    if (note.want_shutdown) {
        err = "NOT_SHUTDOWN";
        return SwarmNotInitResult{"NOT_SHUTDOWN", false, false};
    }
    if (note.want_init) {
        err = "NOT_INIT";
        return SwarmNotInitResult{"NOT_INIT", false, false};
    }
    err.clear();
    return SwarmNotInitResult{"NOTED", false, false};
}

} // namespace modelnet
