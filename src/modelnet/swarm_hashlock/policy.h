// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_HASHLOCK_POLICY_H
#define BITCOIN_MODELNET_SWARM_HASHLOCK_POLICY_H

#include <cstdint>

namespace modelnet {

/**
 * A hashlock is not a qualified route.
 * qualified() stays false. Nothing is broadcast.
 * No bytes and no atoms move.
 */
class SwarmHashlockPolicy {
public:
    bool qualified() const;
    bool broadcast() const;
    int64_t bytes_moved() const;
    int64_t atoms_moved() const;
};

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_HASHLOCK_POLICY_H
