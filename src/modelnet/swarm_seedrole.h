// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_SEEDROLE_H
#define BTX_MODELNET_SWARM_SEEDROLE_H

#include <string>

namespace modelnet {

/** Caller record for a seeder-role decision. Without a device file the node is a seeder and does not train. */
struct SwarmSeedRole {
    std::string node_id;
    bool no_device{false};
    bool want_train{false};
};

/** Classification answer. training stays false on every path. */
struct SwarmSeedRoleResult {
    std::string code;
    bool training{false};
};

/**
 * Keeps a node in the seeder role. training is false on every path.
 * Empty node_id is NODE. no_device is SEEDER, including when want_train
 * is false. want_train is HELD. Otherwise the code is NOTED and err is cleared.
 */
SwarmSeedRoleResult SwarmKeepSeeder(const SwarmSeedRole& node, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_SEEDROLE_H
