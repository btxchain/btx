// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_disputemove.h>

namespace modelnet {

SwarmDisputeStepResult SwarmStepDispute(const SwarmDisputeStep& step, std::string& err)
{
    // A dispute can gather evidence and still settles no outpoint.
    SwarmDisputeStepResult result;
    result.settled = false;
    result.broadcast = false;
    result.atoms = 0;

    if (step.dispute_id.empty()) {
        result.code = "DISPUTE";
        err = "DISPUTE";
        result.state = SwarmDisputeMove::Open;
        return result;
    }

    if (step.state == SwarmDisputeMove::Open) {
        result.code = "NOTED";
        err.clear();
        result.state = SwarmDisputeMove::Evidence;
        return result;
    }

    if (step.state == SwarmDisputeMove::Evidence) {
        if (!step.receipt_signed) {
            result.code = "RECEIPT";
            err = "RECEIPT";
            result.state = SwarmDisputeMove::Evidence;
            return result;
        }
        result.code = "NOTED";
        err.clear();
        result.state = SwarmDisputeMove::Accepted;
        return result;
    }

    if (step.state == SwarmDisputeMove::Refused) {
        result.code = "REFUSED";
        err = "REFUSED";
        result.state = SwarmDisputeMove::Refused;
        return result;
    }

    if (step.state == SwarmDisputeMove::Accepted) {
        if (!step.outpoint_known || step.want_settle) {
            result.code = "HELD";
            err = "HELD";
            result.state = SwarmDisputeMove::Accepted;
            return result;
        }
        result.code = "UNSETTLED";
        err = "UNSETTLED";
        result.state = SwarmDisputeMove::Accepted;
        return result;
    }

    result.settled = false;
    result.broadcast = false;
    result.atoms = 0;
    result.code = "DISPUTE";
    err = "DISPUTE";
    result.state = SwarmDisputeMove::Open;
    return result;
}

} // namespace modelnet
