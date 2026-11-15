// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_ckptonly.h>

#include <string>

namespace modelnet {

SwarmCkptOnlyResult SwarmNoteCkptOnly(const SwarmCkptOnly& claim, std::string& err)
{
    SwarmCkptOnlyResult result;
    result.trusted = false;
    // A checkpoint-only claim is not trust.
    if (claim.claim_id.empty()) {
        result.code = "CLAIM";
        result.trusted = false;
        err = "CLAIM";
        return result;
    }
    if (claim.checkpoint_only) {
        result.code = "NOT_TRUST";
        result.trusted = false;
        err = "NOT_TRUST";
        return result;
    }
    if (claim.want_trust) {
        result.code = "HELD";
        result.trusted = false;
        err = "HELD";
        return result;
    }
    result.code = "NOTED";
    result.trusted = false;
    err.clear();
    return result;
}

} // namespace modelnet
