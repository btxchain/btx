// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnoresearchkey2.h>

#include <string>

namespace modelnet {

SwarmNotNoResearchKey2Result SwarmNoteNotNoResearchKey2(const SwarmNotNoResearchKey2& note, std::string& err)
{
    SwarmNotNoResearchKey2Result result;
    // A research key is not a spend key.
    result.spent = false;
    result.atoms = 0;
    if (note.key_id.empty()) {
        result.code = "KEY";
        result.spent = false;
        result.atoms = 0;
        err = "KEY";
        return result;
    }
    if (note.research) {
        result.code = "NOT_SPEND";
        result.spent = false;
        result.atoms = 0;
        err = "NOT_SPEND";
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
