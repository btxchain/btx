// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_modelneton.h>

namespace modelnet {

SwarmModelNetOnResult SwarmKeepModelNetOn(const SwarmModelNetOn& node, std::string& err)
{
    // ModelNet stays on by default.
    SwarmModelNetOnResult result;
    result.disabled = false;
    if (node.node_id.empty()) {
        result.code = "NODE";
        result.disabled = false;
        err = "NODE";
        return result;
    }
    if (node.want_disable) {
        result.code = "HELD";
        result.disabled = false;
        err = "HELD";
        return result;
    }
    result.code = "NOTED";
    result.disabled = false;
    err.clear();
    return result;
}

} // namespace modelnet
