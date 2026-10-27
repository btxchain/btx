// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_presence.h>

namespace modelnet {

SwarmPresenceResult SwarmAcceptPresenceLocal(const SwarmLocalPresenceRequest& presence, std::string& err)
{
    // A local presence can be kept and does not connect or publish an address.
    if (presence.node_id.empty()) {
        err = "NODE";
        return SwarmPresenceResult{"NODE", false, false, 0};
    }
    if (presence.rtt_ms < 0) {
        err = "RANGE";
        return SwarmPresenceResult{"RANGE", false, false, 0};
    }
    if (presence.want_connect) {
        err = "HELD";
        return SwarmPresenceResult{"HELD", false, false, 1};
    }
    err.clear();
    return SwarmPresenceResult{"NOTED", false, false, 1};
}

} // namespace modelnet
