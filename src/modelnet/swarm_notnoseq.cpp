// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnoseq.h>

#include <cstdint>
#include <string>

namespace modelnet {

SwarmNotNoSeqResult SwarmNoteNotNoSeq(const SwarmNotNoSeq& note, std::string& err)
{
    SwarmNotNoSeqResult result;
    result.stepped = false;
    result.l1_txs = 0;
    // A clearing batch is one sequence step and creates no L1 transaction per payment.
    if (note.batch_id.empty()) {
        result.code = "BATCH";
        result.stepped = false;
        result.l1_txs = 0;
        err = "BATCH";
        return result;
    }
    if (note.want_step) {
        result.code = "ONE_STEP";
        result.stepped = false;
        result.l1_txs = 0;
        err = "ONE_STEP";
        return result;
    }
    result.code = "NOTED";
    result.stepped = false;
    result.l1_txs = 0;
    err.clear();
    return result;
}

} // namespace modelnet
