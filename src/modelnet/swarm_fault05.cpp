// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_fault05.h>

namespace modelnet {

SwarmFault05Result SwarmRecoverFault05(const SwarmFault05& in, std::string& err)
{
    SwarmFault05Result out;
    out.committed = false;
    out.bytes_moved = false;
    out.broadcast = false;

    if (in.worker_id.empty() || in.work_id.empty()) {
        out.code = "WORKER";
        out.reassigned = false;
        out.recovered = false;
        out.payment_preserved = false;
        err = "WORKER";
        return out;
    }

    if (in.result_sent && !in.durable) {
        out.code = "LOST";
        out.recovered = false;
        out.reassigned = false;
        out.payment_preserved = in.payment_claim;
        err = "LOST";
        return out;
    }

    if (in.durable && in.want_reassign) {
        out.code = "REASSIGNED";
        out.recovered = true;
        out.reassigned = true;
        out.committed = false;
        out.payment_preserved = in.payment_claim;
        err.clear();
        return out;
    }

    if (in.result_sent && in.durable) {
        out.code = "DURABLE";
        out.recovered = true;
        out.reassigned = false;
        out.committed = false;
        out.payment_preserved = in.payment_claim;
        err.clear();
        return out;
    }

    out.code = "NOTED";
    out.recovered = false;
    out.reassigned = false;
    out.payment_preserved = in.payment_claim;
    err.clear();
    return out;
}

} // namespace modelnet
