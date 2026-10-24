// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnoresearch.h>

#include <string>

namespace modelnet {

SwarmNotNoResearchResult SwarmNoteNotNoResearch(const SwarmNotNoResearch& note, std::string& err)
{
    SwarmNotNoResearchResult result;
    result.spent = false;
    result.atoms = 0;
    // A research key never receives a spend key and spends nothing.
    if (note.key_id.empty()) {
        result.code = "KEY";
        result.spent = false;
        result.atoms = 0;
        err = "KEY";
        return result;
    }
    if (note.research_key) {
        result.code = "NO_SPEND";
        result.spent = false;
        result.atoms = 0;
        err = "NO_SPEND";
        return result;
    }
    if (note.want_spend) {
        result.code = "NO_SPEND";
        result.spent = false;
        result.atoms = 0;
        err = "NO_SPEND";
        return result;
    }
    result.code = "NOTED";
    result.spent = false;
    result.atoms = 0;
    err.clear();
    return result;
}

} // namespace modelnet
