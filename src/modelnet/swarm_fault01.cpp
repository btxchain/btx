// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_fault01.h>

#include <string>

namespace modelnet {

SwarmFault01Result SwarmRecoverFault01(const SwarmFault01& in, std::string& err)
{
    SwarmFault01Result result;
    // A disappeared coordinator commits nothing and moves nothing.
    result.committed = false;
    result.bytes_moved = false;
    result.broadcast = false;
    if (in.coord_id.empty() || in.work_id.empty()) {
        result.code = "COORD";
        result.committed = false;
        result.reassigned = false;
        result.recovered = false;
        result.payment_preserved = false;
        result.bytes_moved = false;
        result.broadcast = false;
        err = "COORD";
        return result;
    }
    if (in.want_commit) {
        // A disappeared leader commits nothing.
        result.code = "STALE";
        result.committed = false;
        result.recovered = false;
        result.reassigned = false;
        result.payment_preserved = in.payment_claim;
        result.bytes_moved = false;
        result.broadcast = false;
        err = "STALE";
        return result;
    }
    if (in.pending && !in.durable) {
        result.code = "LOST";
        result.committed = false;
        result.recovered = false;
        result.reassigned = false;
        result.payment_preserved = in.payment_claim;
        result.bytes_moved = false;
        result.broadcast = false;
        err = "LOST";
        return result;
    }
    if (in.durable && in.want_reassign) {
        result.code = "REASSIGNED";
        result.recovered = true;
        result.reassigned = true;
        result.committed = false;
        result.payment_preserved = in.payment_claim;
        result.bytes_moved = false;
        result.broadcast = false;
        err.clear();
        return result;
    }
    if (in.durable) {
        result.code = "DURABLE";
        result.recovered = true;
        result.reassigned = false;
        result.committed = false;
        result.payment_preserved = in.payment_claim;
        result.bytes_moved = false;
        result.broadcast = false;
        err.clear();
        return result;
    }
    result.code = "NOTED";
    result.recovered = false;
    result.committed = false;
    result.reassigned = false;
    result.payment_preserved = in.payment_claim;
    result.bytes_moved = false;
    result.broadcast = false;
    err.clear();
    return result;
}

} // namespace modelnet
