// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_natpub.h>

namespace modelnet {

SwarmNatPubResult SwarmNoteNatPub(const SwarmNatPub& node, std::string& err)
{
    // NAT traversal publishes no address.
    if (node.node_id.empty()) {
        err = "NODE";
        return SwarmNatPubResult{"NODE", false};
    }
    if (node.want_publish) {
        err = "HELD";
        return SwarmNatPubResult{"HELD", false};
    }
    err.clear();
    return SwarmNatPubResult{"NOTED", false};
}

} // namespace modelnet
