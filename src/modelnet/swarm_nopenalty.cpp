// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_nopenalty.h>

#include <string>

namespace modelnet {

SwarmPenaltyResult SwarmNotePenalty(const SwarmPenaltyNote& note, std::string& err)
{
    SwarmPenaltyResult result;
    result.secp_penalty = false;
    if (note.channel_id.empty()) {
        result.code = "PENALTY";
        result.secp_penalty = false;
        err = "PENALTY";
        return result;
    }
    // There is no secp256k1 penalty and nothing is broadcast.
    // This wins even when stale_state is true.
    if (note.want_secp_penalty) {
        result.code = "NO_PENALTY";
        result.secp_penalty = false;
        err = "NO_PENALTY";
        return result;
    }
    // Stale state is a hashlock remedy, not a penalty.
    if (note.stale_state) {
        result.code = "HASHLOCK";
        result.secp_penalty = false;
        err.clear();
        return result;
    }
    result.code = "NOTED";
    result.secp_penalty = false;
    err.clear();
    return result;
}

} // namespace modelnet
