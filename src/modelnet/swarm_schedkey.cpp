// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_schedkey.h>

namespace modelnet {

SwarmSchedKeyResult SwarmNoteSchedKey(const SwarmSchedKey& note, std::string& err)
{
    SwarmSchedKeyResult result;
    result.spend_armed = false;
    if (note.scheduler_id.empty()) {
        result.code = "KEY";
        result.spend_armed = false;
        err = "KEY";
        return result;
    }
    // The scheduler never receives a spend key. Do not sign. Do not broadcast.
    if (note.want_spend_key) {
        result.code = "NO_KEY";
        result.spend_armed = false;
        err = "NO_KEY";
        return result;
    }
    result.code = "NOTED";
    result.spend_armed = false;
    err.clear();
    return result;
}

} // namespace modelnet
