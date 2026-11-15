// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_visiblehead.h>

namespace modelnet {

SwarmHeadVisibilityResult SwarmNoteHeadVisibility(const SwarmHeadVisibility& note, std::string& err)
{
    SwarmHeadVisibilityResult result;
    result.visible = false;
    if (note.head_id.empty()) {
        result.code = "HEAD";
        err = "HEAD";
        return result;
    }
    if (!note.graduated) {
        result.code = "PRIVATE";
        err = "PRIVATE";
        return result;
    }
    if (note.public_requested) {
        result.visible = false;
        result.code = "HELD";
        err.clear();
        return result;
    }
    result.visible = false;
    result.code = "NOTED";
    err.clear();
    return result;
}

} // namespace modelnet
