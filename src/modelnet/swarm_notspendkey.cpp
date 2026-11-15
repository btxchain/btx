// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notspendkey.h>

#include <string>

namespace modelnet {

SwarmNotSpendKeyResult SwarmNoteNotSpendKey(const SwarmNotSpendKey& note, std::string& err)
{
    SwarmNotSpendKeyResult result;
    result.signed_spend = false;
    result.broadcast = false;
    // The research scheduler never receives a spend key. This note does
    // not sign or broadcast.
    if (note.scheduler_id.empty()) {
        result.code = "SCHEDULER";
        result.signed_spend = false;
        result.broadcast = false;
        err = "SCHEDULER";
        return result;
    }
    if (note.want_spend) {
        result.code = "NO_KEY";
        result.signed_spend = false;
        result.broadcast = false;
        err = "NO_KEY";
        return result;
    }
    result.code = "NOTED";
    result.signed_spend = false;
    result.broadcast = false;
    err.clear();
    return result;
}

} // namespace modelnet
