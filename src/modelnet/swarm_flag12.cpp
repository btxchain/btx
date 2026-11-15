// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_flag12.h>

#include <string>

namespace modelnet {

SwarmFlag12Result SwarmStageRecover(const SwarmFlag12& in, std::string& err)
{
    SwarmFlag12Result out;
    // A survivor retains durable commitments after the coordinator is gone.
    // committed, broadcast, passed, and bytes_moved stay false.
    // This does not kill a process.
    if (in.survivor_id.empty() || in.work_id.empty()) {
        out.code = "NODE";
        out.continued = false;
        out.recovered = false;
        out.payment_preserved = false;
        out.committed = false;
        out.broadcast = false;
        out.passed = false;
        out.bytes_moved = false;
        err = "NODE";
        return out;
    }
    if (in.want_pass) {
        out.code = "UNQUALIFIED";
        out.continued = false;
        out.recovered = false;
        out.payment_preserved = in.payment_claim;
        out.committed = false;
        out.broadcast = false;
        out.passed = false;
        out.bytes_moved = false;
        err = "UNQUALIFIED";
        return out;
    }
    if (!in.durable) {
        out.code = "LOST";
        out.continued = false;
        out.recovered = false;
        out.payment_preserved = in.payment_claim;
        out.committed = false;
        out.broadcast = false;
        out.passed = false;
        out.bytes_moved = false;
        err = "LOST";
        return out;
    }
    if (in.want_continue) {
        out.code = "DURABLE";
        out.continued = true;
        out.recovered = true;
        out.payment_preserved = in.payment_claim;
        out.committed = false;
        out.broadcast = false;
        out.passed = false;
        out.bytes_moved = false;
        err.clear();
        return out;
    }
    out.code = "NOTED";
    out.continued = false;
    out.recovered = true;
    out.payment_preserved = in.payment_claim;
    out.committed = false;
    out.broadcast = false;
    out.passed = false;
    out.bytes_moved = false;
    err.clear();
    return out;
}

} // namespace modelnet
