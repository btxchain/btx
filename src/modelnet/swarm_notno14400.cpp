// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notno14400.h>

namespace modelnet {

SwarmNotNo14400Result SwarmNoteNotNo14400(const SwarmNotNo14400& note, std::string& err)
{
    SwarmNotNo14400Result result;
    result.closed = false;
    result.l1_txs = 0;
    // 160 blocks at 90 seconds is 14400 seconds and is not a wall-clock close.
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
