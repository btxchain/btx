// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_fault13.h>

namespace modelnet {

SwarmFault13Result SwarmRecoverFault13(const SwarmFault13& in, std::string& err)
{
    SwarmFault13Result result;
    // A payment service crash after earning and before settlement settles nothing.
    result.settled = false;
    result.recovered = false;
    result.payment_preserved = false;
    result.broadcast = false;
    result.committed = false;

    if (in.earn_id.empty()) {
        result.code = "EARN";
        result.settled = false;
        result.recovered = false;
        result.payment_preserved = false;
        result.broadcast = false;
        result.committed = false;
        err = "EARN";
        return result;
    }
    if (in.want_settle) {
        result.code = "HELD";
        result.settled = false;
        result.broadcast = false;
        result.recovered = false;
        result.payment_preserved = in.payment_claim;
        result.committed = false;
        err.clear();
        return result;
    }
    if (in.earned && !in.durable) {
        result.code = "LOST";
        result.recovered = false;
        result.payment_preserved = in.payment_claim;
        result.settled = false;
        result.broadcast = false;
        result.committed = false;
        err = "LOST";
        return result;
    }
    if (in.earned && in.durable) {
        // The durable earn itself is the preserved claim.
        result.code = "EARNED";
        result.recovered = true;
        result.payment_preserved = true;
        result.settled = false;
        result.broadcast = false;
        result.committed = false;
        err.clear();
        return result;
    }
    result.code = "NOTED";
    result.recovered = false;
    result.payment_preserved = in.payment_claim;
    result.settled = false;
    result.broadcast = false;
    result.committed = false;
    err.clear();
    return result;
}

} // namespace modelnet
