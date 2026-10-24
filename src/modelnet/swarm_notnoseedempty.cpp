// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnoseedempty.h>

#include <string>

namespace modelnet {

SwarmNotNoSeedEmptyResult SwarmNoteNotNoSeedEmpty(const SwarmNotNoSeedEmpty& note, std::string& err)
{
    SwarmNotNoSeedEmptyResult result;
    result.seeded = false;
    result.seeds = 0;
    // Model DNS seeds stay empty.
    if (note.node_id.empty()) {
        result.code = "NODE";
        result.seeded = false;
        result.seeds = 0;
        err = "NODE";
        return result;
    }
    if (note.want_seed) {
        result.code = "EMPTY";
        result.seeded = false;
        result.seeds = 0;
        err = "EMPTY";
        return result;
    }
    result.code = "NOTED";
    result.seeded = false;
    result.seeds = 0;
    err.clear();
    return result;
}

} // namespace modelnet
