// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnol1.h>

#include <string>

namespace modelnet {

SwarmNotNoL1Result SwarmNoteNotNoL1(const SwarmNotNoL1& note, std::string& err)
{
    SwarmNotNoL1Result result;
    result.broadcast = false;
    result.l1_txs = 0;
    if (note.batch_id.empty()) {
        result.code = "BATCH";
        result.broadcast = false;
        result.l1_txs = 0;
        err = "BATCH";
        return result;
    }
    // A clearing batch broadcasts no L1 transaction.
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
