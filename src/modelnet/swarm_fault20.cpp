// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_fault20.h>

#include <string>

namespace modelnet {

SwarmFault20Result SwarmRecoverFault20(const SwarmFault20& in, std::string& err)
{
    SwarmFault20Result result;
    // A disappeared coordinator never commits, broadcasts, or moves bytes.
    result.continued = false;
    result.recovered = false;
    result.payment_preserved = false;
    result.committed = false;
    result.broadcast = false;
    result.bytes_moved = false;
    if (in.coord_id.empty()) {
        result.code = "COORD";
        result.continued = false;
        result.recovered = false;
        result.payment_preserved = false;
        result.committed = false;
        result.broadcast = false;
        result.bytes_moved = false;
        err = "COORD";
        return result;
    }
    if (in.survivor_id.empty()) {
        result.code = "NO_SURVIVOR";
        result.continued = false;
        result.recovered = false;
        result.payment_preserved = in.payment_claim;
        result.committed = false;
        result.broadcast = false;
        result.bytes_moved = false;
        err = "NO_SURVIVOR";
        return result;
    }
    if (!in.durable) {
        result.code = "LOST";
        result.continued = false;
        result.recovered = false;
        result.payment_preserved = in.payment_claim;
        result.committed = false;
        result.broadcast = false;
        result.bytes_moved = false;
        err = "LOST";
        return result;
    }
    if (in.want_continue) {
        result.code = "DURABLE";
        result.continued = true;
        result.recovered = true;
        result.payment_preserved = in.payment_claim;
        result.committed = false;
        result.broadcast = false;
        result.bytes_moved = false;
        err.clear();
        return result;
    }
    result.code = "NOTED";
    result.continued = false;
    result.recovered = true;
    result.payment_preserved = in.payment_claim;
    result.committed = false;
    result.broadcast = false;
    result.bytes_moved = false;
    err.clear();
    return result;
}

} // namespace modelnet
