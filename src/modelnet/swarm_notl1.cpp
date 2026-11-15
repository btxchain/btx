// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notl1.h>

#include <string>

namespace modelnet {

SwarmNotL1Result SwarmNoteNotL1(const SwarmNotL1& note, std::string& err)
{
    SwarmNotL1Result result;
    result.broadcast = false;
    result.l1_txs = 0;
    if (note.payment_id.empty()) {
        result.code = "PAYMENT";
        result.broadcast = false;
        result.l1_txs = 0;
        err = "PAYMENT";
        return result;
    }
    // A pool payment does not create an L1 transaction.
    if (note.want_broadcast) {
        result.code = "NOT_BROADCAST";
        result.broadcast = false;
        result.l1_txs = 0;
        err = "NOT_BROADCAST";
        return result;
    }
    result.code = "NOTED";
    result.broadcast = false;
    result.l1_txs = 0;
    err.clear();
    return result;
}

} // namespace modelnet
