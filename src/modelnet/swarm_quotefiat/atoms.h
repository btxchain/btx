// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_QUOTEFIAT_ATOMS_H
#define BITCOIN_MODELNET_SWARM_QUOTEFIAT_ATOMS_H

#include <cstdint>

namespace modelnet {

/**
 * Atom total reported for this plane.
 * stored_sum is the sum already on the book. Quote does not add to it.
 */
class SwarmQuoteFiatAtoms {
public:
    int64_t reported(int64_t stored_sum) const;
};

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_QUOTEFIAT_ATOMS_H
