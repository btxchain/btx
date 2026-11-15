// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_SCRIPTMESH_POLICY_H
#define BITCOIN_MODELNET_SWARM_SCRIPTMESH_POLICY_H

#include <cstdint>

namespace modelnet {

/**
 * Observers for a claim-leaf plane.
 * A built leaf is unqualified. There is no secp penalty.
 * No bytes move and nothing is broadcast.
 */
class SwarmScriptMeshPolicy {
public:
    bool qualified() const;
    bool secp_penalty() const;
    int64_t bytes_moved() const;
    bool broadcast() const;
};

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_SCRIPTMESH_POLICY_H
