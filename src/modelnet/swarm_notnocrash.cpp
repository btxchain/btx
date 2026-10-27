// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnocrash.h>

#include <string>

namespace modelnet {

SwarmNotNoCrashResult SwarmNoteNotNoCrash(const SwarmNotNoCrash& note, std::string& err)
{
    SwarmNotNoCrashResult result;
    result.spent = false;
    result.atoms = 0;
    // A crash does not spend.
    if (note.node_id.empty()) {
        result.code = "NODE";
        result.spent = false;
        result.atoms = 0;
        err = "NODE";
        return result;
    }
    if (note.crashed) {
        result.code = "HELD";
        result.spent = false;
        result.atoms = 0;
        err = "HELD";
        return result;
    }
    if (note.want_spend) {
        result.code = "HELD";
        result.spent = false;
        result.atoms = 0;
        err = "HELD";
        return result;
    }
    result.code = "NOTED";
    result.spent = false;
    result.atoms = 0;
    err.clear();
    return result;
}

} // namespace modelnet
