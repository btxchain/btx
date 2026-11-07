// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notniche.h>

namespace modelnet {

SwarmNotNicheResult SwarmNoteNotNiche(const SwarmNotNiche& note, std::string& err)
{
    SwarmNotNicheResult result;
    result.merged = false;
    if (note.niche_id.empty()) {
        result.code = "NICHE";
        result.merged = false;
        err = "NICHE";
        return result;
    }
    // Niches stay separate.
    if (note.want_merge) {
        result.code = "SEPARATE";
        result.merged = false;
        err = "SEPARATE";
        return result;
    }
    result.code = "NOTED";
    result.merged = false;
    err.clear();
    return result;
}

} // namespace modelnet
