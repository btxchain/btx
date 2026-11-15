// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_seedrole.h>

namespace modelnet {

// Without a device file the node is a seeder and does not train.
SwarmSeedRoleResult SwarmKeepSeeder(const SwarmSeedRole& node, std::string& err)
{
    SwarmSeedRoleResult result;
    result.training = false;
    if (node.node_id.empty()) {
        result.code = "NODE";
        err = "NODE";
        result.training = false;
        return result;
    }
    if (node.no_device) {
        result.code = "SEEDER";
        err = "SEEDER";
        result.training = false;
        return result;
    }
    if (node.want_train) {
        result.code = "HELD";
        err = "HELD";
        result.training = false;
        return result;
    }
    result.code = "NOTED";
    err.clear();
    result.training = false;
    return result;
}

} // namespace modelnet
