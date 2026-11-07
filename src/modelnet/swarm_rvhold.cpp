// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_rvhold.h>

namespace modelnet {

// A public rendezvous opens no socket.
SwarmRvHoldResult SwarmHoldRendezvous(const SwarmRvHold& node, std::string& err)
{
    SwarmRvHoldResult result;
    result.opened = false;
    result.published = false;
    if (node.node_id.empty()) {
        result.code = "NODE";
        result.opened = false;
        result.published = false;
        err = "NODE";
        return result;
    }
    if (node.public_rv) {
        result.code = "HELD";
        result.opened = false;
        result.published = false;
        err = "HELD";
        return result;
    }
    if (node.want_open) {
        result.code = "HELD";
        result.opened = false;
        result.published = false;
        err = "HELD";
        return result;
    }
    result.code = "NOTED";
    result.opened = false;
    result.published = false;
    err.clear();
    return result;
}

} // namespace modelnet
