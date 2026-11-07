// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnonichesep2.h>

#include <string>

namespace modelnet {

SwarmNotNoNicheSep2Result SwarmNoteNotNoNicheSep2(const SwarmNotNoNicheSep2& note, std::string& err)
{
    SwarmNotNoNicheSep2Result result;
    result.merged = false;
    // Niches stay separate.
    if (note.niche_id.empty()) {
        result.code = "NICHE";
        result.merged = false;
        err = "NICHE";
        return result;
    }
    if (note.want_merge) {
        result.code = "HELD";
        result.merged = false;
        err = "HELD";
        return result;
    }
    result.code = "NOTED";
    result.merged = false;
    err.clear();
    return result;
}

} // namespace modelnet
