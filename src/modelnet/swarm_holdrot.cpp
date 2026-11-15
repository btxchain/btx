// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_holdrot.h>

namespace modelnet {

// A fixed holdout is not rotating.
SwarmHoldRotResult SwarmNoteHoldRot(const SwarmHoldRot& split, std::string& err)
{
    SwarmHoldRotResult out;
    out.rotated = false;
    if (split.split_id.empty()) {
        out.code = "SPLIT";
        err = "SPLIT";
        return out;
    }
    if (split.fixed_holdout) {
        out.code = "NOT_ROTATING";
        err = "NOT_ROTATING";
        return out;
    }
    if (split.want_rotate) {
        out.code = "HELD";
        err = "HELD";
        return out;
    }
    out.code = "NOTED";
    err.clear();
    return out;
}

} // namespace modelnet
