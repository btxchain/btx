// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnoschedkey.h>

#include <cstdint>
#include <string>

namespace modelnet {

SwarmNotNoSchedKeyResult SwarmNoteNotNoSchedKey(const SwarmNotNoSchedKey& note, std::string& err)
{
    SwarmNotNoSchedKeyResult result;
    result.spent = false;
    result.atoms = 0;
    // The scheduler never receives a spend key and spends nothing.
    if (note.scheduler_id.empty()) {
        result.code = "SCHEDULER";
        result.spent = false;
        result.atoms = 0;
        err = "SCHEDULER";
        return result;
    }
    if (note.scheduler) {
        result.code = "NO_SPEND";
        result.spent = false;
        result.atoms = 0;
        err = "NO_SPEND";
        return result;
    }
    if (note.want_spend) {
        result.code = "NO_SPEND";
        result.spent = false;
        result.atoms = 0;
        err = "NO_SPEND";
        return result;
    }
    result.code = "NOTED";
    result.spent = false;
    result.atoms = 0;
    err.clear();
    return result;
}

} // namespace modelnet
