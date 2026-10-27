// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_nottxid.h>

#include <string>

namespace modelnet {

SwarmNotTxidResult SwarmNoteNotTxid(const SwarmNotTxid& note, std::string& err)
{
    SwarmNotTxidResult result;
    result.stored = false;
    result.broadcast = false;
    // This note stores no broadcast txid.
    if (note.payment_id.empty()) {
        result.code = "PAYMENT";
        result.stored = false;
        result.broadcast = false;
        err = "PAYMENT";
        return result;
    }
    if (note.want_store) {
        result.code = "NOT_STORED";
        result.stored = false;
        result.broadcast = false;
        err = "NOT_STORED";
        return result;
    }
    result.code = "NOTED";
    result.stored = false;
    result.broadcast = false;
    err.clear();
    return result;
}

} // namespace modelnet
