// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnodns.h>

#include <string>

namespace modelnet {

SwarmNotNoDnsResult SwarmNoteNotNoDns(const SwarmNotNoDns& note, std::string& err)
{
    SwarmNotNoDnsResult result;
    result.filled = false;
    result.seeds = 0;
    // Model DNS seeds stay empty. Filling them is refused.
    if (note.seed_id.empty()) {
        result.code = "SEED";
        result.filled = false;
        result.seeds = 0;
        err = "SEED";
        return result;
    }
    if (note.want_fill) {
        result.code = "EMPTY";
        result.filled = false;
        result.seeds = 0;
        err = "EMPTY";
        return result;
    }
    result.code = "NOTED";
    result.filled = false;
    result.seeds = 0;
    err.clear();
    return result;
}

} // namespace modelnet
