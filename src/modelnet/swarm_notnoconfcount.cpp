// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnoconfcount.h>

#include <string>

namespace modelnet {

SwarmNotNoConfCountResult SwarmNoteNotNoConfCount(const SwarmNotNoConfCount& note, std::string& err)
{
    SwarmNotNoConfCountResult result;
    result.broadcast = false;
    result.l1_txs = 0;
    // A confirmation count does not broadcast.
    if (note.tx_id.empty()) {
        result.code = "TX";
        result.broadcast = false;
        result.l1_txs = 0;
        err = "TX";
        return result;
    }
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
