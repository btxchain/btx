// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnoniche.h>

#include <string>

namespace modelnet {

SwarmNotNoNicheResult SwarmNoteNotNoNiche(const SwarmNotNoNiche& note, std::string& err)
{
    SwarmNotNoNicheResult result;
    result.merged = false;
    result.shared = false;
    // Distinct niches stay separate.
    if (note.niche_id.empty()) {
        result.code = "NICHE";
        result.merged = false;
        result.shared = false;
        err = "NICHE";
        return result;
    }
    if (!note.same_niche) {
        result.code = "SEPARATE";
        result.merged = false;
        result.shared = false;
        err = "SEPARATE";
        return result;
    }
    if (note.want_merge) {
        result.code = "SEPARATE";
        result.merged = false;
        result.shared = false;
        err = "SEPARATE";
        return result;
    }
    result.code = "NOTED";
    result.merged = false;
    result.shared = false;
    err.clear();
    return result;
}

} // namespace modelnet
