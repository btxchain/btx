// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnohtlcsigner2.h>

#include <string>

namespace modelnet {

SwarmNotNoHtlcSigner2Result SwarmNoteNotNoHtlcSigner2(const SwarmNotNoHtlcSigner2& note, std::string& err)
{
    SwarmNotNoHtlcSigner2Result result;
    result.claimed = false;
    result.atoms = 0;
    // A claim key that is not the signer claims nothing.
    if (note.claim_id.empty()) {
        result.code = "CLAIM";
        result.claimed = false;
        result.atoms = 0;
        err = "CLAIM";
        return result;
    }
    if (note.non_signer) {
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
