// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_TOKGATE_QUIET_H
#define BITCOIN_MODELNET_SWARM_TOKGATE_QUIET_H

#include <cstdint>

namespace modelnet {

/**
 * What this plane is not allowed to do.
 * running() stays false. launched() stays false. gpu() stays false.
 * bytes_moved() stays 0.
 * There is no method that starts a process, opens a socket, or moves bytes.
 */
class SwarmTokenGateQuiet {
public:
    bool running() const;
    bool launched() const;
    bool gpu() const;
    int64_t bytes_moved() const;
};

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_TOKGATE_QUIET_H
