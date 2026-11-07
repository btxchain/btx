// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnosess.h>

namespace modelnet {

SwarmNotNoSessResult SwarmNoteNotNoSess(const SwarmNotNoSess& note, std::string& err)
{
    SwarmNotNoSessResult result;
    result.connected = false;
    result.mtls = false;
    if (note.peer_id.empty()) {
        result.code = "PEER";
        err = "PEER";
        return result;
    }
    if (note.want_session) {
        result.code = "NO_SESSION";
        err = "NO_SESSION";
        return result;
    }
    result.code = "NOTED";
    err.clear();
    return result;
}

} // namespace modelnet
