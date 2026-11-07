// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_SANDBOXGATE_QUIET_H
#define BITCOIN_MODELNET_SWARM_SANDBOXGATE_QUIET_H

#include <cstdint>
#include <string>

namespace modelnet {

/**
 * What this plane is not allowed to do.
 * launched() stays false. connected() stays false. gpu() stays false.
 * bytes_moved() stays 0. automatic_spend() stays "0".
 * There is no method that sets launched or connected.
 */
class SwarmSandboxGateQuiet {
public:
    bool launched() const;
    bool connected() const;
    bool gpu() const;
    int64_t bytes_moved() const;
    std::string automatic_spend() const;
};

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_SANDBOXGATE_QUIET_H
