// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnotrustckpt.h>

namespace modelnet {

SwarmNotNoTrustCkptResult SwarmNoteNotNoTrustCkpt(const SwarmNotNoTrustCkpt& note, std::string& err)
{
    SwarmNotNoTrustCkptResult result;
    result.trusted = false;
    result.bytes_moved = false;
    if (note.claim_id.empty()) {
        result.code = "CLAIM";
        result.trusted = false;
        result.bytes_moved = false;
        err = "CLAIM";
        return result;
    }
    if (note.checkpoint_only) {
        result.code = "NOT_TRUST";
        result.trusted = false;
        result.bytes_moved = false;
        err = "NOT_TRUST";
        return result;
    }
    if (note.want_trust) {
        result.code = "HELD";
        result.trusted = false;
        result.bytes_moved = false;
        err = "HELD";
        return result;
    }
    result.code = "NOTED";
    result.trusted = false;
    result.bytes_moved = false;
    err.clear();
    return result;
}

} // namespace modelnet
