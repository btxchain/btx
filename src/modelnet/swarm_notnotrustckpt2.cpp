// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnotrustckpt2.h>

namespace modelnet {

SwarmNotNoTrustCkpt2Result SwarmNoteNotNoTrustCkpt2(const SwarmNotNoTrustCkpt2& note, std::string& err)
{
    SwarmNotNoTrustCkpt2Result result;
    result.trusted = false;
    if (note.claim_id.empty()) {
        result.code = "CLAIM";
        result.trusted = false;
        err = "CLAIM";
        return result;
    }
    if (note.checkpoint_only) {
        result.code = "NOT_TRUST";
        result.trusted = false;
        err = "NOT_TRUST";
        return result;
    }
    if (note.want_trust) {
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
