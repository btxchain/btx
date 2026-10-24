// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnosecp.h>

#include <string>

namespace modelnet {

SwarmNotNoSecpResult SwarmNoteNotNoSecp(const SwarmNotNoSecp& note, std::string& err)
{
    SwarmNotNoSecpResult result;
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
        result.code = "REFUSED";
        result.secp_penalty = false;
        result.broadcast = false;
        err = "REFUSED";
        return result;
    }
    result.code = "NOTED";
    result.secp_penalty = false;
    result.broadcast = false;
    err.clear();
    return result;
}

} // namespace modelnet
