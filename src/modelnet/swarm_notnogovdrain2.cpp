// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnogovdrain2.h>

#include <string>

namespace modelnet {

SwarmNotNoGovDrain2Result SwarmNoteNotNoGovDrain2(const SwarmNotNoGovDrain2& note, std::string& err)
{
    // An idle governor drains workers to zero.
    SwarmNotNoGovDrain2Result result;
    result.workers = 0;
    if (note.governor_id.empty()) {
        result.code = "GOVERNOR";
        result.workers = 0;
        err = "GOVERNOR";
        return result;
    }
    // Idle is DRAINED even when want_keep is false.
    if (note.idle) {
        result.code = "DRAINED";
        result.workers = 0;
        err = "DRAINED";
        return result;
    }
    if (note.want_keep) {
        result.code = "HELD";
        result.workers = 0;
        err = "HELD";
        return result;
    }
    result.code = "NOTED";
    result.workers = 0;
    err.clear();
    return result;
}

} // namespace modelnet
