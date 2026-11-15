// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notpay.h>

#include <string>

namespace modelnet {

SwarmNotPayResult SwarmNoteNotPay(const SwarmNotPay& note, std::string& err)
{
    SwarmNotPayResult result;
    result.settled = false;
    result.broadcast = false;
    // Isolated regtest settlement is not done, and nothing is broadcast.
    if (note.invoice_id.empty()) {
        result.code = "INVOICE";
        result.settled = false;
        result.broadcast = false;
        err = "INVOICE";
        return result;
    }
    if (note.want_settle) {
        result.code = "NOT_SETTLED";
        result.settled = false;
        result.broadcast = false;
        err = "NOT_SETTLED";
        return result;
    }
    result.code = "NOTED";
    result.settled = false;
    result.broadcast = false;
    err.clear();
    return result;
}

} // namespace modelnet
