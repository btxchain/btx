// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_FLAG01_H
#define BTX_MODELNET_SWARM_FLAG01_H

#include <string>

namespace modelnet {

/**
 * Flagship stage 1 acquire: a local gate for an openly licensed
 * immutable artifact.
 *
 * passed, bytes_moved, and broadcast stay false on every path.
 * staged is true only when the local preconditions hold.
 * This does not claim a GPU host verified the artifact.
 */
struct SwarmFlag01 {
    std::string artifact_id;
    int hash_len{0};
    bool license_open{false};
    bool want_pass{false};
};

/**
 * Outcome of the local acquire gate. passed, bytes_moved, and broadcast
 * stay false on every path. verified stays false: this does not claim a
 * GPU host verified the artifact.
 */
struct SwarmFlag01Result {
    std::string code;
    bool staged{false};
    bool verified{false};
    bool passed{false};
    bool bytes_moved{false};
    bool broadcast{false};
};

/**
 * Local gate for an openly licensed immutable artifact.
 * Order, first match wins: an empty artifact_id is ARTIFACT and every
 * bool stays false. hash_len other than 32 is HASH. A license that is
 * not open is LICENSE. want_pass is UNQUALIFIED. Otherwise the gate is
 * STAGED, err is cleared, and the hash length and open license are
 * recorded as the local preconditions. staged is true only on that path.
 * verified stays false. passed, bytes_moved, and broadcast stay false.
 * This does not claim a GPU host verified the artifact.
 */
SwarmFlag01Result SwarmStageAcquire(const SwarmFlag01& in, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_FLAG01_H
