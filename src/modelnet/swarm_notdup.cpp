// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notdup.h>

#include <string>

namespace modelnet {

SwarmNotDupResult SwarmNoteNotDup(const SwarmNotDup& note, std::string& err)
{
    SwarmNotDupResult result;
    result.accepted = false;
    // A duplicate work receipt after reconnect is not this live case.
    if (note.receipt_id.empty()) {
        result.code = "RECEIPT";
        result.accepted = false;
        err = "RECEIPT";
        return result;
    }
    if (note.want_accept) {
        result.code = "NOT_LIVE";
        result.accepted = false;
        err = "NOT_LIVE";
        return result;
    }
    result.code = "NOTED";
    result.accepted = false;
    err.clear();
    return result;
}

} // namespace modelnet
