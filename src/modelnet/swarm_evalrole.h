// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_EVALROLE_H
#define BITCOIN_MODELNET_SWARM_EVALROLE_H

#include <string>

namespace modelnet {

struct SwarmEvalRole {
    std::string node_id;
    bool no_device;
    bool want_train;
};

struct SwarmEvalRoleResult {
    std::string code;
    bool training;
};

SwarmEvalRoleResult SwarmKeepEvaluator(const SwarmEvalRole& node, std::string& err);

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_EVALROLE_H
