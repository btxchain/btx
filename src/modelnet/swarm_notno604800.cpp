// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notno604800.h>

namespace modelnet {

SwarmNotNo604800Result SwarmNoteNotNo604800(const SwarmNotNo604800& note, std::string& err)
{
    SwarmNotNo604800Result result;
    result.closed = false;
    result.l1_txs = 0;
    // 6720 blocks at 90 seconds is 604800 seconds and is not a wall-clock close.
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
