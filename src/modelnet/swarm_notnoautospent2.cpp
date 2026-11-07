// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnoautospent2.h>

#include <string>

namespace modelnet {

SwarmNotNoAutoSpent2Result SwarmNoteNotNoAutoSpent2(const SwarmNotNoAutoSpent2& note, std::string& err)
{
    SwarmNotNoAutoSpent2Result result;
    // Automatic spend stays zero.
    result.armed = false;
    result.atoms = 0;
    if (note.spend_id.empty()) {
        result.code = "SPEND";
        result.armed = false;
        result.atoms = 0;
        err = "SPEND";
        return result;
    }
    if (note.want_set) {
        result.code = "HELD";
        result.armed = false;
        result.atoms = 0;
        err = "HELD";
        return result;
    }
    result.code = "NOTED";
    result.armed = false;
    result.atoms = 0;
    err.clear();
    return result;
}

} // namespace modelnet
