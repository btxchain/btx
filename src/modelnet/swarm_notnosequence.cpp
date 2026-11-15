// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnosequence.h>

#include <cstdint>
#include <string>

namespace modelnet {

SwarmNotNoSequenceResult SwarmNoteNotNoSequence(const SwarmNotNoSequence& note, std::string& err)
{
    SwarmNotNoSequenceResult result;
    result.stepped = false;
    result.l1_txs = 0;
    // A clearing batch takes no extra sequence step from this note.
    if (note.batch_id.empty()) {
        result.code = "BATCH";
        result.stepped = false;
        result.l1_txs = 0;
        err = "BATCH";
        return result;
    }
    if (note.want_step) {
        result.code = "HELD";
        result.stepped = false;
        result.l1_txs = 0;
        err = "HELD";
        return result;
    }
    result.code = "NOTED";
    result.stepped = false;
    result.l1_txs = 0;
    err.clear();
    return result;
}

} // namespace modelnet
