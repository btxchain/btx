// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnopairs.h>

namespace modelnet {

SwarmNotNoPairsResult SwarmNoteNotNoPairs(const SwarmNotNoPairs& note, std::string& err)
{
    SwarmNotNoPairsResult result;
    result.unfrozen = false;
    result.applied = 0;
    // INTEGER_LINEAR and INTEGER_MODEL stay eight frozen pairs.
    if (note.model_id.empty()) {
        result.code = "MODEL";
        result.unfrozen = false;
        result.applied = 0;
        err = "MODEL";
        return result;
    }
    if (note.pair_count != 8) {
        result.code = "FROZEN";
        result.unfrozen = false;
        result.applied = 0;
        err = "FROZEN";
        return result;
    }
    if (note.want_unfreeze) {
        result.code = "FROZEN";
        result.unfrozen = false;
        result.applied = 0;
        err = "FROZEN";
        return result;
    }
    result.code = "NOTED";
    result.unfrozen = false;
    result.applied = 0;
    err.clear();
    return result;
}

} // namespace modelnet
