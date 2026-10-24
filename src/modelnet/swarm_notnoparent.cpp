// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnoparent.h>

namespace modelnet {

SwarmNotNoParentResult SwarmNoteNotNoParent(const SwarmNotNoParent& note, std::string& err)
{
    SwarmNotNoParentResult result;
    result.replaced = false;
    result.trained = false;
    // An unqualified candidate leaves the parent in place and does not train.
    if (note.candidate_id.empty()) {
        result.code = "CANDIDATE";
        result.replaced = false;
        result.trained = false;
        err = "CANDIDATE";
        return result;
    }
    if (!note.qualified) {
        result.code = "KEPT";
        result.replaced = false;
        result.trained = false;
        err = "KEPT";
        return result;
    }
    if (note.want_replace) {
        result.code = "HELD";
        result.replaced = false;
        result.trained = false;
        err = "HELD";
        return result;
    }
    result.code = "NOTED";
    result.replaced = false;
    result.trained = false;
    err.clear();
    return result;
}

} // namespace modelnet
