// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_preimagebind.h>

namespace modelnet {

// A preimage bind claims nothing unless the length is 32 and the signer is present, and even then this record does not spend.
SwarmPreimageBindResult SwarmBindPreimageLocal(const SwarmPreimageBind& bind, std::string& err)
{
    SwarmPreimageBindResult result;
    result.claimed = false;
    result.atoms = 0;

    if (bind.claim_id.empty()) {
        result.code = "CLAIM";
        err = "CLAIM";
        return result;
    }
    if (bind.length != 32) {
        result.code = "PREIMAGE";
        err = "PREIMAGE";
        return result;
    }
    if (!bind.signer) {
        result.code = "SIGNER";
        err = "SIGNER";
        return result;
    }
    if (bind.want_claim) {
        result.code = "HELD";
        err = "HELD";
        return result;
    }
    result.code = "NOTED";
    err.clear();
    return result;
}

} // namespace modelnet
