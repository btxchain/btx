// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_privateoff.h>

namespace modelnet {

// Without a device file, private prompts stay off.
SwarmPrivateOffResult SwarmKeepPrivateOff(const SwarmPrivateOff& node, std::string& err)
{
    SwarmPrivateOffResult result;
    result.enabled = false;
    if (node.node_id.empty()) {
        result.code = "NODE";
        err = "NODE";
        result.enabled = false;
        return result;
    }
    if (node.no_device) {
        result.code = "NOT_PRIVATE";
        err = "NOT_PRIVATE";
        result.enabled = false;
        return result;
    }
    if (node.want_enable) {
        result.code = "HELD";
        err = "HELD";
        result.enabled = false;
        return result;
    }
    result.code = "NOTED";
    err.clear();
    result.enabled = false;
    return result;
}

} // namespace modelnet
