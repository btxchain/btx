// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_fault10.h>

namespace modelnet {

SwarmFault10Result SwarmRecoverFault10(const SwarmFault10& in, std::string& err)
{
    SwarmFault10Result result;
    // Candidate promotion is interrupted. Nothing is promoted, committed, or broadcast.
    result.promoted = false;
    result.recovered = false;
    result.committed = false;
    result.broadcast = false;

    if (in.candidate_id.empty()) {
        result.code = "CANDIDATE";
        result.promoted = false;
        result.recovered = false;
        result.committed = false;
        result.broadcast = false;
        err = "CANDIDATE";
        return result;
    }
    if (in.interrupted) {
        result.code = "GATE";
        result.promoted = false;
        result.recovered = false;
        result.committed = false;
        result.broadcast = false;
        err = "GATE";
        return result;
    }
    if (in.want_promote) {
        result.code = "HELD";
        result.promoted = false;
        result.recovered = false;
        result.committed = false;
        result.broadcast = false;
        err.clear();
        return result;
    }
    if (in.durable) {
        result.code = "DURABLE";
        result.promoted = false;
        result.recovered = true;
        result.committed = false;
        result.broadcast = false;
        err.clear();
        return result;
    }
    result.code = "NOTED";
    result.promoted = false;
    result.recovered = false;
    result.committed = false;
    result.broadcast = false;
    err.clear();
    return result;
}

} // namespace modelnet
