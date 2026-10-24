// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notfrozen.h>

#include <string>

namespace modelnet {

SwarmNotFrozenResult SwarmNoteNotFrozen(const SwarmNotFrozen& note, std::string& err)
{
    SwarmNotFrozenResult result;
    result.unfrozen = false;
    if (note.pair_id.empty()) {
        result.code = "PAIR";
        result.unfrozen = false;
        err = "PAIR";
        return result;
    }
    // INTEGER_LINEAR and INTEGER_MODEL stay eight frozen pairs.
    if (note.pair_count != 8 || note.want_unfreeze) {
        result.code = "FROZEN";
        result.unfrozen = false;
        err = "FROZEN";
        return result;
    }
    result.code = "NOTED";
    result.unfrozen = false;
    err.clear();
    return result;
}

} // namespace modelnet
