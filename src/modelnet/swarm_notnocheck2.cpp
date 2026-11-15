// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnocheck2.h>

#include <string>

namespace modelnet {

SwarmNotNoCheck2Result SwarmNoteNotNoCheck2(const SwarmNotNoCheck2& note, std::string& err)
{
    // A checkpoint-only claim is not trust. trusted and admitted stay
    // false on every path.
    SwarmNotNoCheck2Result result;
    result.trusted = false;
    result.admitted = false;
    if (note.claim_id.empty()) {
        result.code = "CLAIM";
        result.trusted = false;
        result.admitted = false;
        err = "CLAIM";
        return result;
    }
    if (note.checkpoint_only) {
        result.code = "NOT_TRUST";
        result.trusted = false;
        result.admitted = false;
        err = "NOT_TRUST";
        return result;
    }
    if (note.want_trust) {
        result.code = "HELD";
        result.trusted = false;
        result.admitted = false;
        err = "HELD";
        return result;
    }
    result.code = "NOTED";
    result.trusted = false;
    result.admitted = false;
    err.clear();
    return result;
}

} // namespace modelnet
