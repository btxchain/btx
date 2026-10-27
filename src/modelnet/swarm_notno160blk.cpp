// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notno160blk.h>

namespace modelnet {

SwarmNotNo160BlkResult SwarmNoteNotNo160Blk(const SwarmNotNo160Blk& note, std::string& err)
{
    SwarmNotNo160BlkResult result;
    result.closed = false;
    result.l1_txs = 0;
    // A 160-block close margin is not a wall-clock guarantee and this note closes nothing.
    if (note.channel_id.empty()) {
        result.code = "CHANNEL";
        result.closed = false;
        result.l1_txs = 0;
        err = "CHANNEL";
        return result;
    }
    if (note.want_close) {
        result.code = "NOT_WALLCLOCK";
        result.closed = false;
        result.l1_txs = 0;
        err = "NOT_WALLCLOCK";
        return result;
    }
    result.code = "NOTED";
    result.closed = false;
    result.l1_txs = 0;
    err.clear();
    return result;
}

} // namespace modelnet
