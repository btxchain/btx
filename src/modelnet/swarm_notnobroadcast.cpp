// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnobroadcast.h>

#include <string>

namespace modelnet {

SwarmNotNoBroadcastResult SwarmNoteNotNoBroadcast(const SwarmNotNoBroadcast& note, std::string& err)
{
    SwarmNotNoBroadcastResult result;
    result.broadcast = false;
    result.l1_txs = 0;
    // Nothing is broadcast on mainnet.
    if (note.chain_id.empty()) {
        result.code = "CHAIN";
        result.broadcast = false;
        result.l1_txs = 0;
        err = "CHAIN";
        return result;
    }
    if (note.mainnet) {
        result.code = "NOT_BROADCAST";
        result.broadcast = false;
        result.l1_txs = 0;
        err = "NOT_BROADCAST";
        return result;
    }
    if (note.want_broadcast) {
        result.code = "HELD";
        result.broadcast = false;
        result.l1_txs = 0;
        err = "HELD";
        return result;
    }
    result.code = "NOTED";
    result.broadcast = false;
    result.l1_txs = 0;
    err.clear();
    return result;
}

} // namespace modelnet
