// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notresearchkey.h>

namespace modelnet {

SwarmNotResearchKeyResult SwarmNoteNotResearchKey(const SwarmNotResearchKey& note, std::string& err)
{
    SwarmNotResearchKeyResult result;
    result.spend_key = false;
    result.broadcast = false;
    if (note.key_id.empty()) {
        result.code = "KEY";
        result.spend_key = false;
        result.broadcast = false;
        err = "KEY";
        return result;
    }
    // A research key never receives a spend key.
    if (note.want_spend) {
        result.code = "NO_KEY";
        result.spend_key = false;
        result.broadcast = false;
        err = "NO_KEY";
        return result;
    }
    result.code = "NOTED";
    result.spend_key = false;
    result.broadcast = false;
    err.clear();
    return result;
}

} // namespace modelnet
