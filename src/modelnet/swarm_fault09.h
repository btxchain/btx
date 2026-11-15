// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_FAULT09_H
#define BTX_MODELNET_SWARM_FAULT09_H

#include <string>

namespace modelnet {

/**
 * Live fault 9: a model artifact is partially transferred.
 * Local recovery only. accepted, bytes_moved, committed, and broadcast
 * stay false on every path. This does not accept a partial artifact,
 * move bytes, commit, or broadcast.
 */
struct SwarmFault09 {
    std::string artifact_id;
    bool complete{false};
    bool want_accept{false};
};

/**
 * Outcome of a partial artifact transfer.
 * accepted, bytes_moved, committed, and broadcast stay false on every path.
 */
struct SwarmFault09Result {
    std::string code;
    bool accepted{false};
    bool bytes_moved{false};
    bool committed{false};
    bool broadcast{false};
};

/**
 * Classify a partial model-artifact transfer.
 * Order, first match wins:
 * 1. An empty artifact_id is ARTIFACT. Every result bool stays false
 *    and err is ARTIFACT.
 * 2. A transfer that is not complete is INCOMPLETE, even if want_accept
 *    is set. accepted and bytes_moved stay false. err is INCOMPLETE.
 * 3. want_accept is HELD. accepted and bytes_moved stay false.
 *    err is cleared.
 * 4. Otherwise NOTED. accepted and bytes_moved stay false.
 *    err is cleared.
 * accepted, bytes_moved, committed, and broadcast stay false on every path.
 */
SwarmFault09Result SwarmRecoverFault09(const SwarmFault09& in, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_FAULT09_H
