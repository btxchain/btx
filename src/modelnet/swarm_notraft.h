// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_NOTRAFT_H
#define BTX_MODELNET_SWARM_NOTRAFT_H

#include <string>

namespace modelnet {

/**
 * A local note about one process log. want_cluster asks this note to treat
 * that log as a network Raft cluster.
 *
 * One process log is not a network Raft cluster. clustered stays false on
 * every path.
 */
struct SwarmNotRaft {
    std::string node_id;
    bool want_cluster{false};
};

/**
 * Outcome of noting one process log. clustered stays false on every path:
 * one process log is not a network Raft cluster.
 */
struct SwarmNotRaftResult {
    std::string code;
    bool clustered{false};
};

/**
 * Note one process log without treating it as a network Raft cluster.
 * Order, first match wins: an empty node_id is NODE. want_cluster is
 * NOT_CLUSTER. Otherwise the note is NOTED and err is clear.
 * clustered stays false on every path.
 */
SwarmNotRaftResult SwarmNoteNotRaft(const SwarmNotRaft& note, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_NOTRAFT_H
