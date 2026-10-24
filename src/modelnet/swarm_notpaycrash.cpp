// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notpaycrash.h>

#include <string>

namespace modelnet {

SwarmNotPayCrashResult SwarmNoteNotPayCrash(const SwarmNotPayCrash& note, std::string& err)
{
    SwarmNotPayCrashResult result;
    result.settled = false;
    result.broadcast = false;
    // A payment service crash after earning and before settlement broadcasts nothing.
    if (note.earn_id.empty()) {
        result.code = "EARN";
        result.settled = false;
        result.broadcast = false;
        err = "EARN";
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
