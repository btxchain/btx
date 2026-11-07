// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notclearing.h>

#include <string>

namespace modelnet {

SwarmNotClearingResult SwarmNoteNotClearing(const SwarmNotClearing& note, std::string& err)
{
    SwarmNotClearingResult result;
    result.settled = false;
    result.broadcast = false;
    result.l1_txs = 0;
    // This note does not settle a clearing batch or broadcast.
    if (note.batch_id.empty()) {
        result.code = "BATCH";
        result.settled = false;
        result.broadcast = false;
        result.l1_txs = 0;
        err = "BATCH";
        return result;
    }
    if (note.want_settle) {
        result.code = "NOT_SETTLED";
        result.settled = false;
        result.broadcast = false;
        result.l1_txs = 0;
        err = "NOT_SETTLED";
        return result;
    }
    result.code = "NOTED";
    result.settled = false;
    result.broadcast = false;
    result.l1_txs = 0;
    err.clear();
    return result;
}

} // namespace modelnet
