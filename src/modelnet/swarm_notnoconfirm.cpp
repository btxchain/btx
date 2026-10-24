// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnoconfirm.h>

#include <string>

namespace modelnet {

SwarmNotNoConfirmResult SwarmNoteNotNoConfirm(const SwarmNotNoConfirm& note, std::string& err)
{
    SwarmNotNoConfirmResult result;
    result.broadcast = false;
    result.l1_txs = 0;
    // A confirmation count does not broadcast a transaction.
    if (note.tx_id.empty()) {
        result.code = "TX";
        result.broadcast = false;
        result.l1_txs = 0;
        err = "TX";
        return result;
    }
    if (note.want_broadcast) {
        result.code = "CONFIRMED_WITHOUT_BROADCAST";
        result.broadcast = false;
        result.l1_txs = 0;
        err = "CONFIRMED_WITHOUT_BROADCAST";
        return result;
    }
    result.code = "NOTED";
    result.broadcast = false;
    result.l1_txs = 0;
    err.clear();
    return result;
}

} // namespace modelnet
