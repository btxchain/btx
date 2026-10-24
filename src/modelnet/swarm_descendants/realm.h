// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_DESCENDANTS_REALM_H
#define BITCOIN_MODELNET_SWARM_DESCENDANTS_REALM_H

#include <cstdint>

namespace modelnet {

/**
 * Status that this plane cannot change.
 * It does not promote a realm, does not mine, moves no bytes, and does
 * not claim a GPU ran. Score acceptance does not graduate a node.
 */
class SwarmDescendantRealm {
public:
    uint64_t bytes_moved() const;
    bool gpu() const;
    bool graduated() const;
    bool promotes_realm() const;
    bool mines() const;
};

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_DESCENDANTS_REALM_H
