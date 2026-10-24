// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnoclear.h>

#include <string>

namespace modelnet {

SwarmNotNoClearResult SwarmNoteNotNoClear(const SwarmNotNoClear& note, std::string& err)
{
    SwarmNotNoClearResult result;
    result.broadcast = false;
    result.l1_txs = 0;
    if (note.batch_id.empty()) {
        result.code = "BATCH";
        result.broadcast = false;
        result.l1_txs = 0;
        err = "BATCH";
        return result;
    }
    // A clearing batch does not broadcast an L1 transaction.
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
