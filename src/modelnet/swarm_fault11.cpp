// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_fault11.h>

#include <string>

namespace modelnet {

SwarmFault11Result SwarmRecoverFault11(const SwarmFault11& in, std::string& err)
{
    SwarmFault11Result result;
    // A regressed canary is not rolled, promoted, or broadcast.
    result.rolled = false;
    result.promoted = false;
    result.broadcast = false;
    if (in.candidate_id.empty()) {
        result.code = "CANDIDATE";
        result.rolled = false;
        result.promoted = false;
        result.broadcast = false;
        err = "CANDIDATE";
        return result;
    }
    if (in.regressed) {
        // Regression wins over a requested roll.
        result.code = "REGRESSION";
        result.rolled = false;
        result.promoted = false;
        result.broadcast = false;
        err = "REGRESSION";
        return result;
    }
    if (in.want_roll) {
        result.code = "HELD";
        result.rolled = false;
        result.promoted = false;
        result.broadcast = false;
        err.clear();
        return result;
    }
    result.code = "NOTED";
    result.rolled = false;
    result.promoted = false;
    result.broadcast = false;
    err.clear();
    return result;
}

} // namespace modelnet
