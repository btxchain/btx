// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_canarygate.h>

namespace modelnet {

SwarmCanaryGateResult SwarmGateCanary(const SwarmCanaryGate& gate, std::string& err)
{
    // A canary regression keeps the parent. This gate does not promote.
    SwarmCanaryGateResult result;
    result.promoted = false;
    result.parent_kept = true;
    if (gate.candidate_id.empty()) {
        result.code = "CANDIDATE";
        result.promoted = false;
        result.parent_kept = true;
        err = "CANDIDATE";
        return result;
    }
    // Regression applies even when want_promote is false.
    if (gate.regression) {
        result.code = "REGRESSION";
        result.promoted = false;
        result.parent_kept = true;
        err = "REGRESSION";
        return result;
    }
    if (!gate.qualified) {
        result.code = "UNQUALIFIED";
        result.promoted = false;
        result.parent_kept = true;
        err = "UNQUALIFIED";
        return result;
    }
    if (gate.want_promote) {
        result.code = "HELD";
        result.promoted = false;
        result.parent_kept = true;
        err = "HELD";
        return result;
    }
    result.code = "NOTED";
    result.promoted = false;
    result.parent_kept = true;
    err.clear();
    return result;
}

} // namespace modelnet
