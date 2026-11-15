// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_NOTONEPROC_H
#define BTX_MODELNET_SWARM_NOTONEPROC_H

#include <string>

namespace modelnet {

/**
 * A local note about one process log. want_cluster asks this note to treat
 * that log as a cluster.
 *
 * One process log is not a cluster. clustered stays false and peers stays
 * 0 on every path.
 */
struct SwarmNotOneProc {
    std::string log_id;
    bool want_cluster{false};
};

/**
 * Outcome of noting one process log. clustered stays false and peers stays
 * 0 on every path. One process log is not a cluster.
 */
struct SwarmNotOneProcResult {
    std::string code;
    bool clustered{false};
    int peers{0};
};

/**
 * Note one process log without treating it as a cluster.
 * Order, first match wins: an empty log_id is LOG. want_cluster is
 * ONE_PROCESS. Otherwise the note is NOTED and err is clear.
 * clustered stays false and peers stays 0 on every path.
 * One process log is not a cluster.
 */
SwarmNotOneProcResult SwarmNoteNotOneProc(const SwarmNotOneProc& note, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_NOTONEPROC_H
