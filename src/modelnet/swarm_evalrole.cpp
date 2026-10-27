// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_evalrole.h>

namespace modelnet {

// Without a device file the node is an evaluator and does not train.
SwarmEvalRoleResult SwarmKeepEvaluator(const SwarmEvalRole& node, std::string& err)
{
    if (node.node_id.empty()) {
        SwarmEvalRoleResult result;
        result.code = "NODE";
        result.training = false;
        err = "NODE";
        return result;
    }
    if (node.no_device) {
        SwarmEvalRoleResult result;
        result.code = "EVALUATOR";
        result.training = false;
        err = "EVALUATOR";
        return result;
    }
    if (node.want_train) {
        SwarmEvalRoleResult result;
        result.code = "HELD";
        result.training = false;
        err = "HELD";
        return result;
    }
    SwarmEvalRoleResult result;
    result.code = "NOTED";
    result.training = false;
    err.clear();
    return result;
}

} // namespace modelnet
