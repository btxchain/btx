// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnopenalty.h>

#include <string>

namespace modelnet {

SwarmNotNoPenaltyResult SwarmNoteNotNoPenalty(const SwarmNotNoPenalty& note, std::string& err)
{
    SwarmNotNoPenaltyResult result;
    result.secp_penalty = false;
    result.applied = false;
    // There is no secp256k1 Lightning penalty.
    if (note.channel_id.empty()) {
        result.code = "CHANNEL";
        result.secp_penalty = false;
        result.applied = false;
        err = "CHANNEL";
        return result;
    }
    if (note.want_penalty) {
        result.code = "REFUSED";
        result.secp_penalty = false;
        result.applied = false;
        err = "REFUSED";
        return result;
    }
    result.code = "NOTED";
    result.secp_penalty = false;
    result.applied = false;
    err.clear();
    return result;
}

} // namespace modelnet
