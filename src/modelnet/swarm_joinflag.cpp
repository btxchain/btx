// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_joinflag.h>

namespace modelnet {

SwarmJoinFlagResult SwarmNoteJoinFlag(const SwarmJoinFlag& flag, std::string& err)
{
    SwarmJoinFlagResult result;
    result.joined = false;
    result.socket_opened = false;
    if (flag.model_id.empty()) {
        result.code = "JOIN";
        result.joined = false;
        result.socket_opened = false;
        err = "JOIN";
        return result;
    }
    // Join-on-acquire does not need an extra startup flag. This wins
    // even when modelnet_on is true.
    if (flag.extra_flag_required) {
        result.code = "NO_FLAG";
        result.joined = false;
        result.socket_opened = false;
        err = "NO_FLAG";
        return result;
    }
    if (!flag.modelnet_on) {
        result.code = "MODELNET";
        result.joined = false;
        result.socket_opened = false;
        err = "MODELNET";
        return result;
    }
    result.code = "NOTED";
    result.joined = false;
    result.socket_opened = false;
    err.clear();
    return result;
}

} // namespace modelnet
