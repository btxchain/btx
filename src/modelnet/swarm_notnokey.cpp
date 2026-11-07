// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnokey.h>

#include <string>

namespace modelnet {

SwarmNotNoKeyResult SwarmNoteNotNoKey(const SwarmNotNoKey& note, std::string& err)
{
    SwarmNotNoKeyResult result;
    result.granted = false;
    result.spent = false;
    // A research key and the scheduler receive no spend key.
    if (note.role_id.empty()) {
        result.code = "ROLE";
        result.granted = false;
        result.spent = false;
        err = "ROLE";
        return result;
    }
    if (note.research_or_scheduler) {
        result.code = "NO_KEY";
        result.granted = false;
        result.spent = false;
        err = "NO_KEY";
        return result;
    }
    if (note.want_spend) {
        result.code = "NO_KEY";
        result.granted = false;
        result.spent = false;
        err = "NO_KEY";
        return result;
    }
    result.code = "NOTED";
    result.granted = false;
    result.spent = false;
    err.clear();
    return result;
}

} // namespace modelnet
