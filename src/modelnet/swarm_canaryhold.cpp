// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_canaryhold.h>

namespace modelnet {

SwarmCanaryHoldResult SwarmHoldCanary(const SwarmCanaryHoldRequest& request, std::string& err)
{
    SwarmCanaryHoldResult result;
    result.activated = false;
    if (request.candidate_id.empty()) {
        result.code = "CANARY";
        err = "CANARY";
        return result;
    }
    if (!request.canary_started) {
        result.code = "NOT_STARTED";
        err = "NOT_STARTED";
        return result;
    }
    if (request.regression) {
        result.code = "REGRESSION";
        err = "REGRESSION";
        return result;
    }
    if (request.want_activate) {
        result.activated = false;
        result.code = "HELD";
        err.clear();
        return result;
    }
    result.activated = false;
    result.code = "NOTED";
    err.clear();
    return result;
}

} // namespace modelnet
