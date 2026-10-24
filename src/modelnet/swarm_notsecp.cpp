// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notsecp.h>

#include <string>

namespace modelnet {

SwarmNotSecpResult SwarmNoteNotSecp(const SwarmNotSecp& note, std::string& err)
{
    SwarmNotSecpResult result;
    result.secp_penalty = false;
    result.broadcast = false;
    // There is no secp256k1 Lightning penalty.
    if (note.channel_id.empty()) {
        result.code = "CHANNEL";
        result.secp_penalty = false;
        result.broadcast = false;
        err = "CHANNEL";
        return result;
    }
    if (note.want_penalty) {
        result.code = "NO_PENALTY";
        result.secp_penalty = false;
        result.broadcast = false;
        err = "NO_PENALTY";
        return result;
    }
    result.code = "NOTED";
    result.secp_penalty = false;
    result.broadcast = false;
    err.clear();
    return result;
}

} // namespace modelnet
