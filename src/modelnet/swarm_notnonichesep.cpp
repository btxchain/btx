// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnonichesep.h>

#include <string>

namespace modelnet {

SwarmNotNoNicheSepResult SwarmNoteNotNoNicheSep(const SwarmNotNoNicheSep& note, std::string& err)
{
    SwarmNotNoNicheSepResult result;
    result.shared = false;
    result.bytes_moved = false;
    // Niches stay separate.
    if (note.niche_id.empty()) {
        result.code = "NICHE";
        result.shared = false;
        result.bytes_moved = false;
        err = "NICHE";
        return result;
    }
    if (!note.same_niche) {
        result.code = "SEPARATE";
        result.shared = false;
        result.bytes_moved = false;
        err = "SEPARATE";
        return result;
    }
    if (note.want_share) {
        result.code = "NOT_SHARED";
        result.shared = false;
        result.bytes_moved = false;
        err = "NOT_SHARED";
        return result;
    }
    result.code = "NOTED";
    result.shared = false;
    result.bytes_moved = false;
    err.clear();
    return result;
}

} // namespace modelnet
