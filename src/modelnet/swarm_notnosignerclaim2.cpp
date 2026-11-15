// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnosignerclaim2.h>

#include <string>

namespace modelnet {

SwarmNotNoSignerClaim2Result SwarmNoteNotNoSignerClaim2(const SwarmNotNoSignerClaim2& note, std::string& err)
{
    SwarmNotNoSignerClaim2Result result;
    result.claimed = false;
    result.atoms = 0;
    // A non-signer claims nothing.
    if (note.claim_id.empty()) {
        result.code = "CLAIM";
        result.claimed = false;
        result.atoms = 0;
        err = "CLAIM";
        return result;
    }
    if (!note.signer) {
        result.code = "NOT_SIGNER";
        result.claimed = false;
        result.atoms = 0;
        err = "NOT_SIGNER";
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
