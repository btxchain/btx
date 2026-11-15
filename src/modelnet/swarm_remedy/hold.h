// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_REMEDY_HOLD_H
#define BITCOIN_MODELNET_SWARM_REMEDY_HOLD_H

#include <cstdint>

namespace modelnet {

/**
 * Observers for the revocation plane.
 * Nothing is broadcast, no bytes move, and nothing is mined.
 */
class SwarmRemedyHold {
public:
    bool broadcast() const;
    int64_t bytes_moved() const;
    bool mined() const;
};

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_REMEDY_HOLD_H
