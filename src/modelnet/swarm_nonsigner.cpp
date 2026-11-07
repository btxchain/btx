// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_nonsigner.h>

namespace modelnet {

// A non-signer claims nothing.
SwarmNonSignerResult SwarmNoteNonSigner(const SwarmNonSigner& claim, std::string& err)
{
    SwarmNonSignerResult result;
    result.claimed = false;
    result.atoms = 0;

    if (claim.claim_id.empty()) {
        result.code = "CLAIM";
        err = "CLAIM";
        return result;
    }
    if (!claim.signer) {
        result.code = "NOT_SIGNER";
        err = "NOT_SIGNER";
        return result;
    }
    if (claim.want_claim) {
        result.code = "HELD";
        err = "HELD";
        return result;
    }
    result.code = "NOTED";
    err.clear();
    return result;
}

} // namespace modelnet
