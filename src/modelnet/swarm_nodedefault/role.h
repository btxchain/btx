// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_NODEDEFAULT_ROLE_H
#define BITCOIN_MODELNET_SWARM_NODEDEFAULT_ROLE_H

#include <modelnet/swarm_nodedefault/limits.h>

namespace modelnet {

/**
 * Seeder, evaluator, and slot count for the default node.
 * seeder() and evaluator() are true from construction. slots() is 1.
 * This does not open a socket and does not spawn a process.
 */
class SwarmNodeDefaultRole {
public:
    bool seeder() const;
    bool evaluator() const;
    int slots() const;

private:
    bool m_seeder{kSwarmNodeDefaultSeeder};
    bool m_evaluator{kSwarmNodeDefaultEvaluator};
    int m_slots{kSwarmNodeDefaultSlots};
};

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_NODEDEFAULT_ROLE_H
