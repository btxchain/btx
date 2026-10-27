// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_AGENTEXEC_QUIET_H
#define BITCOIN_MODELNET_SWARM_AGENTEXEC_QUIET_H

#include <cstdint>
#include <string>

namespace modelnet {

/**
 * Inspectors that stay fixed because this executor never leaves the process.
 * launched() stays false. connected() stays false. gpu() stays false.
 * broadcast() stays false. atoms_moved() stays 0. automatic_spend() stays "0".
 * There is no method that changes these values.
 */
class SwarmAgentExecQuiet {
public:
    bool launched() const;
    bool connected() const;
    bool gpu() const;
    bool broadcast() const;
    int64_t atoms_moved() const;
    std::string automatic_spend() const;
};

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_AGENTEXEC_QUIET_H
