// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_fault03.h>

#include <string>

namespace modelnet {

SwarmFault03Result SwarmRecoverFault03(const SwarmFault03& in, std::string& err)
{
    SwarmFault03Result out;
    // Local recovery only. committed, bytes_moved, and broadcast stay false.
    if (in.epoch_id.empty() || in.current_epoch.empty()) {
        out.code = "EPOCH";
        out.committed = false;
        out.recovered = false;
        out.payment_preserved = false;
        out.bytes_moved = false;
        out.broadcast = false;
        err = "EPOCH";
        return out;
    }
    if (in.epoch_id != in.current_epoch || in.want_commit) {
        out.code = "STALE";
        out.committed = false;
        out.recovered = false;
        out.payment_preserved = in.payment_claim;
        out.bytes_moved = false;
        out.broadcast = false;
        err = "STALE";
        return out;
    }
    if (in.durable) {
        out.code = "DURABLE";
        out.committed = false;
        out.recovered = true;
        out.payment_preserved = in.payment_claim;
        out.bytes_moved = false;
        out.broadcast = false;
        err.clear();
        return out;
    }
    out.code = "NOTED";
    out.committed = false;
    out.recovered = false;
    out.payment_preserved = in.payment_claim;
    out.bytes_moved = false;
    out.broadcast = false;
    err.clear();
    return out;
}

} // namespace modelnet
