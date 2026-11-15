// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_seqonce.h>

#include <cstdint>

namespace modelnet {

SwarmSequenceBatchResult SwarmNoteSequenceBatch(const SwarmSequenceBatch& batch, std::string& err)
{
    SwarmSequenceBatchResult result;
    result.advanced = false;
    if (batch.payments < 1 || batch.requested_sequence_steps < 1) {
        result.code = "SEQUENCE";
        result.advanced = false;
        err = "SEQUENCE";
        return result;
    }
    // Many payments still use one sequence step. A request for one step
    // per payment is refused. This note does not advance a live channel
    // and does not broadcast.
    if (batch.requested_sequence_steps != 1) {
        result.code = "ONCE";
        result.advanced = false;
        err = "ONCE";
        return result;
    }
    result.code = "NOTED";
    result.advanced = false;
    err.clear();
    return result;
}

} // namespace modelnet
