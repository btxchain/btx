// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_fault02.h>

#include <string>

namespace modelnet {

SwarmFault02Result SwarmRecoverFault02(const SwarmFault02& in, std::string& err)
{
    SwarmFault02Result out;
    // Local recovery only. committed, bytes_moved, and broadcast stay false.
    if (in.lease_id.empty() || in.old_epoch.empty() || in.new_epoch.empty()) {
        out.code = "LEASE";
        out.committed = false;
        out.replaced = false;
        out.recovered = false;
        out.payment_preserved = false;
        out.bytes_moved = false;
        out.broadcast = false;
        err = "LEASE";
        return out;
    }
    if (in.want_commit) {
        out.code = "STALE";
        out.committed = false;
        out.replaced = false;
        out.recovered = false;
        out.payment_preserved = in.payment_claim;
        out.bytes_moved = false;
        out.broadcast = false;
        err = "STALE";
        return out;
    }
    if (!in.lease_expired) {
        out.code = "HELD";
        out.committed = false;
        out.replaced = false;
        out.recovered = false;
        out.payment_preserved = in.payment_claim;
        out.bytes_moved = false;
        out.broadcast = false;
        err.clear();
        return out;
    }
    if (in.new_epoch == in.old_epoch) {
        out.code = "SAME_EPOCH";
        out.committed = false;
        out.replaced = false;
        out.recovered = false;
        out.payment_preserved = in.payment_claim;
        out.bytes_moved = false;
        out.broadcast = false;
        err = "SAME_EPOCH";
        return out;
    }
    if (in.durable) {
        out.code = "REPLACED";
        out.committed = false;
        out.replaced = true;
        out.recovered = true;
        out.payment_preserved = in.payment_claim;
        out.bytes_moved = false;
        out.broadcast = false;
        err.clear();
        return out;
    }
    out.code = "LOST";
    out.committed = false;
    out.replaced = false;
    out.recovered = false;
    out.payment_preserved = in.payment_claim;
    out.bytes_moved = false;
    out.broadcast = false;
    err = "LOST";
    return out;
}

} // namespace modelnet
