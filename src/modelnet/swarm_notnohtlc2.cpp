// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnohtlc2.h>

#include <string>

namespace modelnet {

SwarmNotNoHtlc2Result SwarmNoteNotNoHtlc2(const SwarmNotNoHtlc2& note, std::string& err)
{
    SwarmNotNoHtlc2Result result;
    result.claimed = false;
    result.atoms = 0;
    // A contributor claim that is not a P2MR HTLC leaf claims nothing.
    if (note.claim_id.empty()) {
        result.code = "CLAIM";
        result.claimed = false;
        result.atoms = 0;
        err = "CLAIM";
        return result;
    }
    if (!note.p2mr_leaf) {
        result.code = "NOT_CLAIMED";
        result.claimed = false;
        result.atoms = 0;
        err = "NOT_CLAIMED";
        return result;
    }
    if (note.want_claim) {
        result.code = "HELD";
        result.claimed = false;
        result.atoms = 0;
        err = "HELD";
        return result;
    }
    result.code = "NOTED";
    result.claimed = false;
    result.atoms = 0;
    err.clear();
    return result;
}

} // namespace modelnet
