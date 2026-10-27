// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notraft.h>

#include <string>

namespace modelnet {

SwarmNotRaftResult SwarmNoteNotRaft(const SwarmNotRaft& note, std::string& err)
{
    SwarmNotRaftResult result;
    result.clustered = false;
    // One process log is not a network Raft cluster.
    if (note.node_id.empty()) {
        result.code = "NODE";
        result.clustered = false;
        err = "NODE";
        return result;
    }
    if (note.want_cluster) {
        result.code = "NOT_CLUSTER";
        result.clustered = false;
        err = "NOT_CLUSTER";
        return result;
    }
    result.code = "NOTED";
    result.clustered = false;
    err.clear();
    return result;
}

} // namespace modelnet
