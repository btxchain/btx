// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_fault06.h>

#include <string>

namespace modelnet {

SwarmFault06Result SwarmRecoverFault06(const SwarmFault06& in, std::string& err)
{
    SwarmFault06Result out;
    // A duplicate receipt after reconnection is never accepted.
    if (in.receipt_id.empty()) {
        out.code = "RECEIPT";
        out.accepted = false;
        out.committed = false;
        out.recovered = false;
        out.payment_preserved = false;
        out.bytes_moved = false;
        out.broadcast = false;
        err = "RECEIPT";
        return out;
    }
    if (in.seen_before) {
        out.code = "REPLAY";
        out.accepted = false;
        out.committed = false;
        out.recovered = in.durable;
        out.payment_preserved = in.payment_claim;
        out.bytes_moved = false;
        out.broadcast = false;
        err = "REPLAY";
        return out;
    }
    if (in.want_accept) {
        out.code = "HELD";
        out.accepted = false;
        out.committed = false;
        out.recovered = false;
        out.payment_preserved = in.payment_claim;
        out.bytes_moved = false;
        out.broadcast = false;
        err.clear();
        return out;
    }
    if (in.durable) {
        out.code = "DURABLE";
        out.accepted = false;
        out.committed = false;
        out.recovered = true;
        out.payment_preserved = in.payment_claim;
        out.bytes_moved = false;
        out.broadcast = false;
        err.clear();
        return out;
    }
    out.code = "NOTED";
    out.accepted = false;
    out.committed = false;
    out.recovered = false;
    out.payment_preserved = in.payment_claim;
    out.bytes_moved = false;
    out.broadcast = false;
    err.clear();
    return out;
}

} // namespace modelnet
