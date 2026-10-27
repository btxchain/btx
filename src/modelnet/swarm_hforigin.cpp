// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_hforigin.h>

namespace modelnet {

SwarmHfOriginResult SwarmNoteHfOrigin(const SwarmHfOrigin& note, std::string& err)
{
    SwarmHfOriginResult result;
    result.authority = false;
    if (note.model_id.empty()) {
        result.code = "ORIGIN";
        err = "ORIGIN";
        return result;
    }
    // Hugging Face is an import origin, not lineage authority.
    // NOT_AUTHORITY wins even when hugging_face is true.
    if (note.want_lineage_authority) {
        result.code = "NOT_AUTHORITY";
        err = "NOT_AUTHORITY";
        return result;
    }
    if (note.hugging_face) {
        result.code = "HELD";
        result.authority = false;
        err.clear();
        return result;
    }
    result.code = "NOTED";
    result.authority = false;
    err.clear();
    return result;
}

} // namespace modelnet
