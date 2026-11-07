// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_meterdrain.h>

namespace modelnet {

SwarmMeterDrainResult SwarmNoteMeterDrain(const SwarmMeterDrain& node, std::string& err)
{
    // A metered link drains workers to zero.
    SwarmMeterDrainResult result;
    result.workers = 0;
    if (node.node_id.empty()) {
        result.code = "NODE";
        result.workers = 0;
        err = "NODE";
        return result;
    }
    if (node.metered) {
        result.code = "DRAINED";
        result.workers = 0;
        err = "DRAINED";
        return result;
    }
    if (node.want_run) {
        result.code = "HELD";
        result.workers = 0;
        err = "HELD";
        return result;
    }
    result.code = "NOTED";
    result.workers = 0;
    err.clear();
    return result;
}

} // namespace modelnet
