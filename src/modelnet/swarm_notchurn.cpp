// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notchurn.h>

#include <string>

namespace modelnet {

SwarmNotChurnResult SwarmNoteNotChurn(const SwarmNotChurn& note, std::string& err)
{
    SwarmNotChurnResult result;
    result.recovered = false;
    result.restarted = false;
    if (note.peer_id.empty()) {
        result.code = "PEER";
        result.recovered = false;
        result.restarted = false;
        err = "PEER";
        return result;
    }
    // This note does not observe peer-churn recovery across hosts.
    if (note.want_recover) {
        result.code = "NOT_OBSERVED";
        result.recovered = false;
        result.restarted = false;
        err = "NOT_OBSERVED";
        return result;
    }
    result.code = "NOTED";
    result.recovered = false;
    result.restarted = false;
    err.clear();
    return result;
}

} // namespace modelnet
