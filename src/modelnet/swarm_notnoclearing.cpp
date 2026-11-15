// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnoclearing.h>

#include <cstdint>
#include <string>

namespace modelnet {

SwarmNotNoClearingResult SwarmNoteNotNoClearing(const SwarmNotNoClearing& note, std::string& err)
{
    SwarmNotNoClearingResult result;
    result.paid = false;
    result.l1_txs = 0;
    // A clearing note pays nothing and creates no L1 transaction.
    if (note.batch_id.empty()) {
        result.code = "BATCH";
        result.paid = false;
        result.l1_txs = 0;
        err = "BATCH";
        return result;
    }
    if (note.want_pay) {
        result.code = "NETTED";
        result.paid = false;
        result.l1_txs = 0;
        err = "NETTED";
        return result;
    }
    result.code = "NOTED";
    result.paid = false;
    result.l1_txs = 0;
    err.clear();
    return result;
}

} // namespace modelnet
