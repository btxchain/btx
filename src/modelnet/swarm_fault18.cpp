// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_fault18.h>

namespace modelnet {

SwarmFault18Result SwarmRecoverFault18(const SwarmFault18& in, std::string& err)
{
    SwarmFault18Result result;
    // Dataset authorization withdrawn before training starts. No GPU job.
    result.training = false;
    result.started = false;
    result.broadcast = false;

    if (in.dataset_id.empty() || in.job_id.empty()) {
        result.code = "DATASET";
        result.training = false;
        result.started = false;
        result.broadcast = false;
        err = "DATASET";
        return result;
    }
    if (in.withdrawn) {
        result.code = "NOT_STARTED";
        result.training = false;
        result.started = false;
        result.broadcast = false;
        err = "NOT_STARTED";
        return result;
    }
    if (in.want_train) {
        result.code = "HELD";
        result.training = false;
        result.started = false;
        result.broadcast = false;
        err.clear();
        return result;
    }
    result.code = "NOTED";
    result.training = false;
    result.started = false;
    result.broadcast = false;
    err.clear();
    return result;
}

} // namespace modelnet
