// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnointeger82.h>

#include <string>

namespace modelnet {

SwarmNotNoInteger82Result SwarmNoteNotNoInteger82(const SwarmNotNoInteger82& note, std::string& err)
{
    SwarmNotNoInteger82Result result;
    result.added = false;
    // INTEGER_LINEAR stays eight frozen pairs.
    if (note.pair_id.empty()) {
        result.code = "PAIR";
        result.added = false;
        err = "PAIR";
        return result;
    }
    if (note.want_add) {
        result.code = "HELD";
        result.added = false;
        err = "HELD";
        return result;
    }
    result.code = "NOTED";
    result.added = false;
    err.clear();
    return result;
}

} // namespace modelnet
