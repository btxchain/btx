// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notidentity.h>

namespace modelnet {

SwarmNotIdentityResult SwarmNoteNotIdentity(const SwarmNotIdentity& note, std::string& err)
{
    // This note does not bind a lab identity.
    if (note.node_id.empty()) {
        err = "NODE";
        return SwarmNotIdentityResult{"NODE", false};
    }
    if (note.want_bind) {
        err = "NOT_BOUND";
        return SwarmNotIdentityResult{"NOT_BOUND", false};
    }
    err.clear();
    return SwarmNotIdentityResult{"NOTED", false};
}

} // namespace modelnet
