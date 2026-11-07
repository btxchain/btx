// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notoneproc.h>

#include <string>

namespace modelnet {

SwarmNotOneProcResult SwarmNoteNotOneProc(const SwarmNotOneProc& note, std::string& err)
{
    SwarmNotOneProcResult result;
    result.clustered = false;
    result.peers = 0;
    // One process log is not a cluster.
    if (note.log_id.empty()) {
        result.code = "LOG";
        result.clustered = false;
        result.peers = 0;
        err = "LOG";
        return result;
    }
    if (note.want_cluster) {
        result.code = "ONE_PROCESS";
        result.clustered = false;
        result.peers = 0;
        err = "ONE_PROCESS";
        return result;
    }
    result.code = "NOTED";
    result.clustered = false;
    result.peers = 0;
    err.clear();
    return result;
}

} // namespace modelnet
