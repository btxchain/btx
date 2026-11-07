// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnopreimage32.h>

#include <string>

namespace modelnet {

SwarmNotNoPreimage32Result SwarmNoteNotNoPreimage32(const SwarmNotNoPreimage32& note, std::string& err)
{
    SwarmNotNoPreimage32Result result;
    result.claimed = false;
    result.atoms = 0;
    // A preimage length other than 32 claims nothing.
    if (note.claim_id.empty()) {
        result.code = "CLAIM";
        result.claimed = false;
        result.atoms = 0;
        err = "CLAIM";
        return result;
    }
    if (note.length != 32) {
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
