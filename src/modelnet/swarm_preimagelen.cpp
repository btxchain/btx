// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_preimagelen.h>

namespace modelnet {

SwarmPreimageLenResult SwarmNotePreimageLength(const SwarmPreimageLen& claim, std::string& err)
{
    // A preimage length other than 32 claims nothing.
    SwarmPreimageLenResult result;
    result.claimed = false;
    result.atoms = 0;

    if (claim.claim_id.empty()) {
        result.code = "CLAIM";
        result.claimed = false;
        result.atoms = 0;
        err = "CLAIM";
        return result;
    }
    if (claim.length != 32) {
        result.code = "NOT_CLAIMED";
        result.claimed = false;
        result.atoms = 0;
        err = "NOT_CLAIMED";
        return result;
    }
    if (claim.want_claim) {
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
