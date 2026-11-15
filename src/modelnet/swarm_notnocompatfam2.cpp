// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnocompatfam2.h>

#include <string>

namespace modelnet {

SwarmNotNoCompatFam2Result SwarmNoteNotNoCompatFam2(const SwarmNotNoCompatFam2& note, std::string& err)
{
    SwarmNotNoCompatFam2Result result;
    result.shared = false;
    // Family membership does not share KV pages.
    if (note.family_id.empty()) {
        result.code = "FAMILY";
        result.shared = false;
        err = "FAMILY";
        return result;
    }
    if (note.membership) {
        result.code = "NOT_COMPAT";
        result.shared = false;
        err = "NOT_COMPAT";
        return result;
    }
    if (note.want_share) {
        result.code = "HELD";
        result.shared = false;
        err = "HELD";
        return result;
    }
    result.code = "NOTED";
    result.shared = false;
    err.clear();
    return result;
}

} // namespace modelnet
