// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnooneclose.h>

#include <string>

namespace modelnet {

SwarmNotNoOneCloseResult SwarmNoteNotNoOneClose(const SwarmNotNoOneClose& note, std::string& err)
{
    SwarmNotNoOneCloseResult result;
    result.closed = false;
    result.l1_txs = 0;
    // A clearing batch has one close template and this note closes nothing.
    if (note.batch_id.empty()) {
        result.code = "BATCH";
        result.closed = false;
        result.l1_txs = 0;
        err = "BATCH";
        return result;
    }
    if (note.want_close_many) {
        result.code = "ONE_CLOSE";
        result.closed = false;
        result.l1_txs = 0;
        err = "ONE_CLOSE";
        return result;
    }
    result.code = "NOTED";
    result.closed = false;
    result.l1_txs = 0;
    err.clear();
    return result;
}

} // namespace modelnet
