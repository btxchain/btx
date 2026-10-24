// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notdispute.h>

#include <string>

namespace modelnet {

SwarmNotDisputeResult SwarmNoteNotDispute(const SwarmNotDispute& note, std::string& err)
{
    SwarmNotDisputeResult result;
    result.settled = false;
    result.broadcast = false;
    // This note stores no txid, does not mine, and does not broadcast.
    if (note.receipt_id.empty()) {
        result.code = "RECEIPT";
        result.settled = false;
        result.broadcast = false;
        err = "RECEIPT";
        return result;
    }
    if (note.want_settle) {
        result.code = "NOT_SETTLED";
        result.settled = false;
        result.broadcast = false;
        err = "NOT_SETTLED";
        return result;
    }
    result.code = "NOTED";
    result.settled = false;
    result.broadcast = false;
    err.clear();
    return result;
}

} // namespace modelnet
